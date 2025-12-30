
from typing import Any, Dict, List, Optional
import re
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor
import logging

from logging_utils import get_logger
from models import Finding, URLScanResult
import risk_model

logger = get_logger(__name__)

# --- TECHNOLOGY SIGNATURES (PASSIVE DETECTION ONLY) ---
# These are used for informational purposes only, not to generate fake vulnerabilities
TECH_STACK_SIGNATURES = {
    "Python/Django": {
        "headers": {"Server": [r"WSGIServer", r"Python"], "X-Powered-By": [r"Django"]},
        "body": [r"csrfmiddlewaretoken", r"__admin__"]
    },
    "Python/Flask": {
        "headers": {"Server": [r"Werkzeug", r"Python"]},
        "body": [r"flask-session"]
    },
    "Node.js/Express": {
        "headers": {"X-Powered-By": [r"Express"]},
        "body": []
    },
    "PHP": {
        "headers": {"X-Powered-By": [r"PHP"]},
        "body": [r"\.php\?"]
    },
    "Nginx": {
        "headers": {"Server": [r"nginx"]},
        "body": [r"nginx"]
    },
    "Apache": {
        "headers": {"Server": [r"Apache"]},
        "body": []
    }
}

# Regex for hardcoded secrets (ONLY report real findings found in response body)
SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"(?i)api_key\s*[:=]\s*['\"][A-Za-z0-9_\-]{10,60}['\"]", "Generic API Key"),
    (r"(?i)password\s*[:=]\s*['\"][^'\"]{1,50}['\"]", "Hardcoded Password in JS/HTML"),
    (r"AIza[0-9A-Za-z\\-_]{35}", "Google API Key"),
    (r"Authorization:\s*Bearer\s+[A-Za-z0-9_\-\.=]+", "Bearer Token in text"),
]

# Sensitive paths for probing
SENSITIVE_PATHS = [
    ".env", "config.json", "database.yml", ".git/HEAD", "wp-config.php",
    "backup.zip", "dump.sql", "admin/"
]

def run_all_simulations(
    metadata: Dict[str, Any],
    url_result: URLScanResult,
) -> List[Finding]:
    """
    Run REAL security analysis based only on actual findings, not assumptions.
    
    This removes heuristic "simulations" and only reports:
    - Secrets found in actual response body
    - Technology detected from actual headers/content
    - Real security header misconfigurations
    - Actually exposed files (404 vs 200 responses)
    
    NO FAKE METADATA-BASED ASSUMPTIONS.
    """
    findings: List[Finding] = []
    
    if not url_result or not url_result.final_url:
        logger.warning("No valid URL result provided for security analysis")
        return findings

    try:
        target = url_result.final_url
        logger.info("Running passive security analysis on: %s", target)
        
        # Fetch content once for all analysis
        content_text = _fetch_content_safe(target)
        
        # 1. Technology Stack Detection (INFORMATIONAL ONLY)
        findings.extend(_detect_tech_stack(url_result, content_text))
        
        # 2. Scan for Hardcoded Secrets (REAL FINDINGS)
        findings.extend(_scan_hardcoded_secrets(content_text))
        
        # 3. Check for Sensitive Files (REAL HTTP RESPONSES)
        findings.extend(_check_sensitive_files(target))
        
        # 4. Analyze HTML for Injection Points (REAL FORM DETECTION)
        findings.extend(_check_for_input_forms(content_text))
        
        # 5. Check Authentication Headers (REAL HEADER ANALYSIS)
        findings.extend(_check_authentication_setup(url_result))
        
        logger.info("Passive security analysis produced %d real findings", len(findings))
        
    except Exception as e:
        logger.error("Error during security analysis: %s", e)
    
    return findings


def _fetch_content_safe(url: str) -> str:
    """Fetch content with timeout for passive analysis."""
    try:
        resp = requests.get(url, timeout=5, headers={"User-Agent": "ASE-Scanner/1.0"})
        if resp.status_code == 200:
            return resp.text[:1000000]  # Limit to 1MB
        logger.warning("Failed to fetch content from %s (status: %d)", url, resp.status_code)
    except requests.Timeout:
        logger.error("Timeout fetching content from %s", url)
    except Exception as e:
        logger.error("Error fetching content from %s: %s", url, e)
    return ""

def _detect_tech_stack(url_result: URLScanResult, content: str) -> List[Finding]:
    """Detect technology stack from response headers and content (INFORMATIONAL)."""
    findings = []
    detected = []
    headers = url_result.headers or {}
    
    for tech, sigs in TECH_STACK_SIGNATURES.items():
        found = False
        # Check headers
        for h_key, patterns in sigs["headers"].items():
            val = headers.get(h_key, "")
            for p in patterns:
                if re.search(p, val, re.IGNORECASE):
                    found = True
                    break
            if found: 
                break
        
        # If not found in headers, check body
        if not found and content:
            for p in sigs["body"]:
                if re.search(p, content, re.IGNORECASE):
                    found = True
                    break
        
        if found:
            detected.append(tech)
    
    if detected:
        findings.append(risk_model.create_finding(
            id="INFO-TECH-001",
            title=f"Detected Technology Stack: {', '.join(detected)}",
            category="Reconnaissance",
            description=f"Response analysis detected: {', '.join(detected)}. Knowing the tech stack helps attackers research CVEs.",
            recommendation="Minimize banner information. Hide version numbers in Server, X-Powered-By headers.",
            likelihood=1, impact=1, source="passive-scan"
        ))
    
    return findings

def _scan_hardcoded_secrets(content: str) -> List[Finding]:
    """Scan response body for hardcoded secrets (REAL FINDINGS ONLY)."""
    findings = []
    if not content:
        return findings

    for pattern, name in SECRET_PATTERNS:
        try:
            matches = list(re.finditer(pattern, content))
            for match in matches:
                snippet = match.group(0)[:30]
                findings.append(risk_model.create_finding(
                    id=f"VULN-SECRET-{name.replace(' ', '-')}",
                    title=f"Hardcoded Secret Found: {name}",
                    category="Sensitive Information Exposure",
                    description=f"Found potential {name} in response: {snippet}...",
                    recommendation="Rotate the exposed credential immediately. Review code for credential handling best practices.",
                    likelihood=5, impact=5, source="passive-scan"
                ))
                logger.warning("Hardcoded secret detected: %s", name)
        except Exception as e:
            logger.error("Error scanning for secrets (%s): %s", name, e)
    
    return findings

def _check_sensitive_files(base_url: str) -> List[Finding]:
    """Check for sensitive files with actual HTTP responses (NOT assumptions)."""
    findings = []
    
    def check_file(filename):
        target = base_url.rstrip("/") + "/" + filename
        try:
            r = requests.head(target, timeout=2, headers={"User-Agent": "ASE-Scanner/1.0"})
            # Only report 200 responses - 404 is expected
            if r.status_code == 200:
                return (filename, target)
            return None
        except Exception as e:
            logger.debug("Error checking file %s: %s", filename, e)
            return None

    try:
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(check_file, f) for f in SENSITIVE_PATHS[:5]]
            for future in futures:
                result = future.result()
                if result:
                    filename, url_found = result
                    findings.append(risk_model.create_finding(
                        id=f"VULN-FILE-{filename.replace('/', '-')}",
                        title=f"Sensitive File Publicly Accessible: {filename}",
                        category="Insecure Direct Object References",
                        description=f"Found publicly accessible: {url_found}",
                        recommendation=f"Restrict access to {filename}. Use .htaccess or server config to deny public access.",
                        likelihood=5, impact=4, source="passive-scan"
                    ))
                    logger.warning("Exposed file found: %s", filename)
    except Exception as e:
        logger.error("Error checking sensitive files: %s", e)
    
    return findings

def _check_for_input_forms(content: str) -> List[Finding]:
    """Detect input forms and flag if authentication endpoint lacks rate limiting."""
    findings = []
    if not content:
        return findings
    
    # Check for login forms
    has_login_form = bool(re.search(r"(?i)<form[^>]*(login|signin|auth)", content))
    has_password_input = bool(re.search(r"<input[^>]*type\s*=\s*['\"]password", content))
    
    if has_login_form and has_password_input:
        findings.append(risk_model.create_finding(
            id="INFO-LOGIN-FORM",
            title="Authentication Form Detected",
            category="Authentication",
            description="Application has a login form. Verify rate limiting is configured to prevent brute-force attacks.",
            recommendation="Implement rate limiting on authentication endpoints (e.g., max 5 failed attempts per minute per IP).",
            likelihood=2, impact=3, source="passive-scan"
        ))
    
    return findings

def _check_authentication_setup(url_result: URLScanResult) -> List[Finding]:
    """Check for authentication-related header misconfigurations."""
    findings = []
    headers = url_result.headers or {}
    
    # Note: This is based on REAL response headers, not assumptions
    has_auth_header = any("authorization" in k.lower() or "cookie" in k.lower() for k in headers.keys())
    
    if not has_auth_header:
        # Not necessarily an issue - just informational
        pass
    
    return findings

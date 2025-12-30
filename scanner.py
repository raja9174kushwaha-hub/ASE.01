import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import ipaddress
import re

from logging_utils import get_logger
from models import Finding, RiskSummary, URLScanResult
import url_checker, attack_simulator, risk_model, nmap_scanner

logger = get_logger(__name__)


# --- INPUT VALIDATION LAYER ---

BLOCKED_DOMAINS = {
    "google.com", "www.google.com", "google.co.uk",
    "youtube.com", "www.youtube.com",
    "facebook.com", "www.facebook.com",
    "instagram.com", "www.instagram.com",
    "twitter.com", "x.com", "www.x.com",
    "linkedin.com", "www.linkedin.com",
    "amazon.com", "www.amazon.com",
    "microsoft.com", "www.microsoft.com",
    "openai.com", "www.openai.com", "chatgpt.com",
    "reddit.com", "www.reddit.com",
    "github.com", "www.github.com",
}

BLOCKED_IP_RANGES = [
    "127.0.0.1/8",  # Loopback
    "10.0.0.0/8",   # Private
    "172.16.0.0/12",  # Private
    "192.168.0.0/16",  # Private
    "169.254.0.0/16",  # Link-local
    "224.0.0.0/4",     # Multicast
    "255.255.255.255/32",  # Broadcast
]

def validate_target_url(url: str) -> tuple[bool, str]:
    """
    Validate target URL with strict rules.
    
    Returns: (is_valid, result)
    - (False, error_message): invalid target, scan should not proceed
    - (True, normalized_url): valid target, safe to scan
    """
    if not url or not isinstance(url, str):
        return False, "URL is empty or invalid type"
    
    url = url.strip()
    if len(url) < 5 or len(url) > 2048:
        return False, "URL length invalid (5-2048 chars)"
    
    # Ensure valid URL format
    if not (url.startswith("http://") or url.startswith("https://")):
        url = f"https://{url}"
    
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return False, "URL has no hostname"
        
        domain = parsed.netloc.lower()
        
        # Remove port if present
        if ":" in domain:
            domain = domain.split(":")[0]
        
        # Check blocked domains
        if domain in BLOCKED_DOMAINS:
            logger.warning("Blocked domain scan attempt: %s", domain)
            return False, f"Domain {domain} is not allowed for scanning"
        
        # Check if hostname is an IP address
        try:
            ip = ipaddress.ip_address(domain)
            for blocked_range in BLOCKED_IP_RANGES:
                if ip in ipaddress.ip_network(blocked_range, strict=False):
                    logger.warning("Blocked IP range scan attempt: %s", ip)
                    return False, f"IP {ip} is in restricted range (private/reserved)"
        except ValueError:
            # Not an IP address, it's a domain - check for valid TLD
            if not re.match(r"^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$", domain, re.IGNORECASE):
                return False, "Domain has invalid format"
        
        logger.info("Target URL validated: %s", url)
        return True, url
        
    except Exception as e:
        logger.error("URL validation error: %s", e)
        return False, f"URL validation error: {str(e)}"


def validate_ip_address(ip: str) -> tuple[bool, str]:
    """Validate and check IP address."""
    if not ip or not isinstance(ip, str):
        return False, "IP is empty or invalid type"
    
    ip = ip.strip()
    try:
        ip_obj = ipaddress.ip_address(ip)
        
        for blocked_range in BLOCKED_IP_RANGES:
            if ip_obj in ipaddress.ip_network(blocked_range, strict=False):
                logger.warning("Blocked IP scan attempt: %s", ip)
                return False, f"IP {ip} is in restricted range"
        
        logger.info("IP address validated: %s", ip)
        return True, ip
    except ValueError:
        return False, f"{ip} is not a valid IP address"
    except Exception as e:
        logger.error("IP validation error: %s", e)
        return False, f"IP validation error: {str(e)}"


def validate_json_metadata(metadata: Any) -> tuple[bool, str]:
    """Validate JSON metadata structure."""
    if not isinstance(metadata, dict):
        return False, "Metadata must be a dictionary"
    
    if len(str(metadata)) > 10000000:  # 10MB limit
        return False, "Metadata too large (>10MB)"
    
    return True, "OK"


# --- DATA CLASSES ---

@dataclass
class ScanUserInfo:
    """Metadata about the person requesting a scan."""
    name: str
    email: str
    organization: str
    purpose: str


@dataclass
class FullScanResult:
    user: ScanUserInfo
    target_url: str
    ownership_confirmed: bool
    timestamp_utc: str
    url_scan: Optional[URLScanResult]
    findings: List[Finding]
    risk_summary: Optional[RiskSummary]
    nmap_raw: Dict[str, Any]
    error: Optional[str] = None  # Error message if scan failed


# --- SCAN EXECUTION ---

def full_safe_scan(
    user: ScanUserInfo,
    target_url: str,
    ownership_confirmed: bool,
    *,
    include_nmap: bool = True,
) -> FullScanResult:
    """Run a combined, *safe* scan for an **authorised** target.

    This function performs only non‑intrusive checks:
    - a single HTTP GET (with redirects)
    - header & configuration analysis
    - passive security analysis based on actual response
    - optional Nmap scan via local Nmap binary
    
    STRICT INPUT VALIDATION is applied BEFORE scan execution.
    Returns FullScanResult with error field populated if validation fails.
    """

    # VALIDATION STEP 0: Check ownership confirmation
    if not ownership_confirmed:
        error_msg = "Ownership/authorization confirmation required before scanning."
        logger.warning("Scan rejected - no ownership confirmation for %s", user.email)
        return FullScanResult(
            user=user,
            target_url=target_url,
            ownership_confirmed=False,
            timestamp_utc=datetime.utcnow().isoformat() + "Z",
            url_scan=None,
            findings=[],
            risk_summary=None,
            nmap_raw={},
            error=error_msg,
        )

    # VALIDATION STEP 1: Validate target URL
    is_valid, validated_url_or_error = validate_target_url(target_url)
    if not is_valid:
        logger.warning("Scan rejected for %s: invalid target %s (%s)", 
                      user.email, target_url, validated_url_or_error)
        return FullScanResult(
            user=user,
            target_url=target_url,
            ownership_confirmed=ownership_confirmed,
            timestamp_utc=datetime.utcnow().isoformat() + "Z",
            url_scan=None,
            findings=[],
            risk_summary=None,
            nmap_raw={},
            error=validated_url_or_error,
        )

    logger.info(
        "Authorised full_safe_scan started for %s <%s> targeting %s",
        user.name,
        user.email,
        target_url,
    )

    findings: List[Finding] = []
    url_result: Optional[URLScanResult] = None

    # 1) Perform safe URL check
    try:
        url_result = url_checker.perform_safe_url_check(validated_url_or_error)
    except Exception as e:
        logger.error("URL check exception: %s", e)
        url_result = None
    
    if url_result is None:
        logger.warning("URL check failed for %s", target_url)
        return FullScanResult(
            user=user,
            target_url=target_url,
            ownership_confirmed=ownership_confirmed,
            timestamp_utc=datetime.utcnow().isoformat() + "Z",
            url_scan=None,
            findings=[],
            risk_summary=None,
            nmap_raw={},
            error="URL unreachable. Target may be down or blocked by firewall.",
        )
    
    # 2) Analyze URL security headers
    try:
        url_security_findings = url_checker.analyze_url_security(url_result)
        findings.extend(url_security_findings)
        logger.info("URL analysis produced %d findings", len(url_security_findings))
    except Exception as e:
        logger.error("URL analysis error: %s", e)

    # 3) Passive security checks (REAL findings only - no metadata assumptions)
    try:
        passive_findings = attack_simulator.run_all_simulations({}, url_result)
        findings.extend(passive_findings)
        logger.info("Passive analysis produced %d findings", len(passive_findings))
    except Exception as e:
        logger.error("Passive analysis error: %s", e)

    # 4) Optional Nmap network scan
    nmap_raw: Dict[str, Any] = {}
    if include_nmap:
        try:
            nmap_findings, nmap_raw = nmap_scanner.run_nmap_scan(
                target=validated_url_or_error,
                scan_type="fast",
                ports=None,
            )
            findings.extend(nmap_findings)
            logger.info("Nmap scan produced %d findings", len(nmap_findings))
        except Exception as e:
            logger.error("Nmap scan error: %s", e)
            nmap_raw = {"error": str(e), "status": "failed"}

    # 5) Aggregate risk assessment
    risk_summary: Optional[RiskSummary] = None
    if findings:
        try:
            risk_summary = risk_model.aggregate_risk(findings)
        except Exception as e:
            logger.error("Risk aggregation error: %s", e)

    result = FullScanResult(
        user=user,
        target_url=target_url,
        ownership_confirmed=ownership_confirmed,
        timestamp_utc=datetime.utcnow().isoformat() + "Z",
        url_scan=url_result,
        findings=findings,
        risk_summary=risk_summary,
        nmap_raw=nmap_raw,
        error=None,
    )

    logger.info(
        "full_safe_scan complete for %s – %d findings, risk score=%s",
        target_url,
        len(findings),
        getattr(risk_summary, "overall_score", "n/a") if risk_summary else "N/A",
    )

    return result

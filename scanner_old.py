import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
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
    
    Returns: (is_valid, error_message)
    - False: invalid target, should not proceed with scan
    - True: valid target, safe to scan
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
            return False, f"Domain {domain} is not allowed for scanning (restricted platform)"
        
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


@dataclass
class ScanUserInfo:
    """Metadata about the person requesting a scan.

    This is *not* an authentication system, just an explicit record of who
    requested which scan so that the app owner/admin can review usage.
    """

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


def full_safe_scan(
    user: ScanUserInfo,
    target_url: str,
    ownership_confirmed: bool,
    *,
    include_nmap: bool = True,
) -> FullScanResult:
    """Run a combined, *safe* scan for an **authorised** target.

    This function deliberately performs only non‑intrusive checks:
    - a single HTTP GET (with redirects)
    - header & configuration analysis
    - heuristic attack "simulations" based on metadata
    - optional Nmap scan via the local Nmap API wrapper

    The caller is responsible for ensuring that `target_url` belongs to the
    user or that they have explicit permission to test it.
    """

    if not ownership_confirmed:
        raise ValueError(
            "full_safe_scan requires explicit ownership/authorisation confirmation."
        )

    logger.info(
        "Authorised full_safe_scan requested by %s <%s> for %s",
        user.name,
        user.email,
        target_url,
    )

    findings: List[Finding] = []
    url_result: Optional[URLScanResult] = None

    # 1) Safe URL check
    url_result = url_checker.perform_safe_url_check(target_url)
    if url_result is None:
        logger.warning("URL check failed during full_safe_scan for %s", target_url)
    else:
        findings.extend(url_checker.analyze_url_security(url_result))

        # 2) Attack simulations – use empty metadata for now, the Streamlit
        # app can pass richer metadata later if available.
        metadata: Dict[str, Any] = {}
        findings.extend(attack_simulator.run_all_simulations(metadata, url_result))

    # 3) Optional Nmap scan via existing helper (non‑blocking if it fails)
    nmap_raw: Dict[str, Any] = {}
    if include_nmap:
        try:
            nmap_findings, nmap_raw = nmap_scanner.run_nmap_scan(
                target=target_url,
                scan_type="fast",
                ports=None,
            )
            findings.extend(nmap_findings)
        except Exception as exc:  # defensive – do not break the whole scan
            logger.error("Nmap scan failed in full_safe_scan: %s", exc)
            nmap_raw = {"error": str(exc)}

    # 4) Aggregate risk across all findings
    risk_summary: Optional[RiskSummary]
    if findings:
        risk_summary = risk_model.aggregate_risk(findings)
    else:
        risk_summary = None

    result = FullScanResult(
        user=user,
        target_url=target_url,
        ownership_confirmed=ownership_confirmed,
        timestamp_utc=datetime.utcnow().isoformat() + "Z",
        url_scan=url_result,
        findings=findings,
        risk_summary=risk_summary,
        nmap_raw=nmap_raw,
    )

    logger.info(
        "full_safe_scan complete for %s – %d findings, overall score=%s",
        target_url,
        len(findings),
        getattr(risk_summary, "overall_score", "n/a"),
    )

    return result
from typing import List, Optional
from urllib.parse import urlparse

import requests

from logging_utils import get_logger
from models import URLScanResult, Finding
import risk_model

logger = get_logger(__name__)


def perform_safe_url_check(url: str) -> Optional[URLScanResult]:
    """Perform a safe, non-intrusive GET request to inspect basic security aspects.

    Only a single GET request (with redirects) is issued. No fuzzing, payloads,
    or brute-force attempts are performed.
    
    Returns None if the check fails. Does NOT raise exceptions.
    """
    try:
        parsed_target = urlparse(url)
        domain = parsed_target.netloc.lower()
        
        logger.info("Safe GET request starting for %s", url)
        
        resp = requests.get(url, timeout=10, allow_redirects=True)
        
        logger.info("Response received from %s: status=%d", url, resp.status_code)
        
    except requests.ConnectTimeout:
        logger.warning("Connection timeout for %s", url)
        return None
    except requests.ReadTimeout:
        logger.warning("Read timeout for %s", url)
        return None
    except requests.RequestException as exc:
        logger.warning("URL check failed for %s: %s", url, exc)
        return None
    except Exception as e:
        logger.error("Unexpected error in URL check: %s", e)
        return None

    try:
        redirect_chain: List[str] = [url] + [h.url for h in resp.history]
        parsed = urlparse(resp.url)
        https = parsed.scheme.lower() == "https"

        result = URLScanResult(
            original_url=url,
            final_url=resp.url,
            https=https,
            status_code=resp.status_code,
            headers=dict(resp.headers),
            elapsed_ms=resp.elapsed.total_seconds() * 1000.0 if resp.elapsed else 0.0,
            redirect_chain=redirect_chain,
        )
        logger.info(
            "Safe URL check completed for %s: status=%d, https=%s, redirect_chain_len=%d",
            url,
            resp.status_code,
            https,
            len(redirect_chain),
        )
        return result
        
    except Exception as e:
        logger.error("Error parsing URL response: %s", e)
        return None

def analyze_url_security(scan: URLScanResult) -> List[Finding]:
    """Analyze response headers and connection properties and return URL findings.

    This is rule-based only and does not modify the target in any way.
    """
    findings: List[Finding] = []
    headers = {k.lower(): v for k, v in (scan.headers or {}).items()}

    # 1. HTTPS usage
    if not scan.https:
        findings.append(
            risk_model.create_finding(
                id="URL-HTTPS-001",
                title="Connection is not using HTTPS",
                category="Data Protection & Transport",
                description=(
                    "The final URL is served over plain HTTP. Traffic can be intercepted "
                    "or modified by attackers on the network."
                ),
                recommendation=(
                    "Serve the site exclusively over HTTPS with a valid TLS certificate, "
                    "and redirect all HTTP requests to HTTPS."
                ),
                likelihood=5,
                impact=4,
                source="url",
            )
        )

    # 2. HSTS (only meaningful when HTTPS is already in use)
    sts = headers.get("strict-transport-security")
    if scan.https and not sts:
        findings.append(
            risk_model.create_finding(
                id="URL-HSTS-001",
                title="HSTS header missing",
                category="Data Protection & Transport",
                description=(
                    "The response is served over HTTPS but does not include the "
                    "Strict-Transport-Security header. Browsers may still allow "
                    "downgrade to HTTP, exposing users to SSL stripping attacks."
                ),
                recommendation=(
                    "Enable HSTS with an appropriate max-age and includeSubDomains once "
                    "HTTPS is stable across your domains."
                ),
                likelihood=3,
                impact=3,
                source="url",
            )
        )

    # 3. Content Security Policy
    csp = headers.get("content-security-policy")
    if not csp:
        findings.append(
            risk_model.create_finding(
                id="URL-CSP-001",
                title="Content-Security-Policy header missing",
                category="Security Headers",
                description=(
                    "The response does not include a Content-Security-Policy header. "
                    "Without CSP, it is harder to mitigate XSS and content injection bugs."
                ),
                recommendation=(
                    "Define a strict CSP that limits allowed script, style, frame, and "
                    "resource origins. Start with a report-only policy and then enforce it."
                ),
                likelihood=2,
                impact=2,
                source="url",
            )
        )

    # 4. X-Frame-Options
    xfo = headers.get("x-frame-options")
    if not xfo:
        findings.append(
            risk_model.create_finding(
                id="URL-XFO-001",
                title="X-Frame-Options header missing",
                category="Security Headers",
                description=(
                    "The response does not include X-Frame-Options. Without this, the "
                    "site may be vulnerable to clickjacking if embedded in iframes."
                ),
                recommendation=(
                    "Add X-Frame-Options: DENY or SAMEORIGIN, or use the frame-ancestors "
                    "directive in CSP to control framing."
                ),
                likelihood=2,
                impact=2,
                source="url",
            )
        )

    # 5. X-Content-Type-Options
    xcto = headers.get("x-content-type-options", "").lower()
    if xcto != "nosniff":
        findings.append(
            risk_model.create_finding(
                id="URL-XCTO-001",
                title="X-Content-Type-Options not set to 'nosniff'",
                category="Security Headers",
                description=(
                    "The response is missing X-Content-Type-Options: nosniff. Browsers "
                    "may attempt MIME type sniffing, which can enable some attack vectors."
                ),
                recommendation=(
                    "Set X-Content-Type-Options: nosniff on all responses serving "
                    "HTML, JavaScript, or other active content."
                ),
                likelihood=2,
                impact=1,
                source="url",
            )
        )

    # 6. Referrer-Policy
    ref_pol = headers.get("referrer-policy")
    if not ref_pol:
        findings.append(
            risk_model.create_finding(
                id="URL-REF-001",
                title="Referrer-Policy header missing",
                category="Security Headers",
                description=(
                    "Without a Referrer-Policy header, browsers may send full URLs, "
                    "including sensitive path/query data, as the Referer header."
                ),
                recommendation=(
                    "Set a privacy-friendly Referrer-Policy such as 'no-referrer', "
                    "'no-referrer-when-downgrade', or 'strict-origin-when-cross-origin'."
                ),
                likelihood=2,
                impact=1,
                source="url",
            )
        )

    # 7. Permissions-Policy
    perm_pol = headers.get("permissions-policy")
    if not perm_pol:
        findings.append(
            risk_model.create_finding(
                id="URL-PERM-001",
                title="Permissions-Policy header missing",
                category="Security Headers",
                description=(
                    "The response is missing Permissions-Policy. This header helps limit "
                    "access to powerful browser features (camera, geolocation, etc.)."
                ),
                recommendation=(
                    "Define a Permissions-Policy that explicitly enables only the browser "
                    "features your application needs."
                ),
                likelihood=1,
                impact=1,
                source="url",
            )
        )

    # 8. Server information leakage
    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    if server or powered_by:
        value = f"Server: {server!r}, X-Powered-By: {powered_by!r}"
        findings.append(
            risk_model.create_finding(
                id="URL-SERVER-INFO-001",
                title="Server technology information exposed in headers",
                category="Security Misconfiguration",
                description=(
                    "The response exposes server or framework information in headers, "
                    f"which can help attackers fingerprint the stack. ({value})"
                ),
                recommendation=(
                    "Remove or minimize Server and X-Powered-By headers, or configure "
                    "them to use generic values without version numbers."
                ),
                likelihood=2,
                impact=1,
                source="url",
            )
        )

    # 9. Caching behavior
    cache_control = headers.get("cache-control", "")
    pragma = headers.get("pragma", "")
    if not cache_control and not pragma:
        findings.append(
            risk_model.create_finding(
                id="URL-CACHE-001",
                title="Cache-control headers missing",
                category="Data Protection & Transport",
                description=(
                    "No Cache-Control or Pragma headers were found. Sensitive pages "
                    "may end up cached in browsers or intermediary proxies."
                ),
                recommendation=(
                    "For authenticated or sensitive content, use Cache-Control: no-store, "
                    "no-cache, or private as appropriate."
                ),
                likelihood=2,
                impact=2,
                source="url",
            )
        )

    # 10. Content-Type presence
    content_type = headers.get("content-type")
    if not content_type:
        findings.append(
            risk_model.create_finding(
                id="URL-CT-001",
                title="Content-Type header missing",
                category="Security Headers",
                description=(
                    "The response does not declare a Content-Type header. Browsers may "
                    "guess the content type, which can lead to unpredictable behavior."
                ),
                recommendation=(
                    "Always set an explicit and correct Content-Type (e.g., text/html; "
                    "charset=utf-8 or application/json)."
                ),
                likelihood=2,
                impact=1,
                source="url",
            )
        )

    logger.info("URL security analysis produced %d findings", len(findings))
    return findings

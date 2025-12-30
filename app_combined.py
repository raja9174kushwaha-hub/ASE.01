"""
Attack Simulation Engine (ASE) - Combined Single File Version
All modules combined into one file for easy deployment.
"""

import json
import logging
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from collections import defaultdict
from urllib.parse import urlparse

import streamlit as st
import pandas as pd
import requests

# Optional imports for enhanced features
try:
    import plotly.express as px
except ImportError:
    px = None

try:
    from fpdf import FPDF
except ImportError:
    FPDF = None

try:
    import google.generativeai as genai
except ImportError:
    genai = None

# ===========================================================================
# MODELS - Data Classes
# ===========================================================================

@dataclass
class Finding:
    id: str
    title: str
    category: str
    severity: str  # Low, Medium, High
    description: str
    recommendation: str
    likelihood: int  # 1–3
    impact: int  # 1–3
    raw_score: int  # likelihood * impact
    source: str  # "json", "url", "simulation"


@dataclass
class CategoryScore:
    category: str
    score: float  # 0–10
    severity: str  # Low, Medium, High


@dataclass
class RiskSummary:
    overall_score: float  # 0–10
    overall_severity: str
    category_scores: List[CategoryScore] = field(default_factory=list)


@dataclass
class URLScanResult:
    original_url: str
    final_url: str
    https: bool
    status_code: int
    headers: Dict[str, Any]
    elapsed_ms: float
    redirect_chain: List[str] = field(default_factory=list)


# ===========================================================================
# LOGGING UTILITIES
# ===========================================================================

_LOGGING_CONFIGURED = False


def configure_logging(level: int = logging.INFO) -> None:
    """Configure basic logging for the ASE app."""
    global _LOGGING_CONFIGURED
    if _LOGGING_CONFIGURED:
        return

    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    _LOGGING_CONFIGURED = True
    logging.getLogger(__name__).info("Logging configured at level %s", logging.getLevelName(level))


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Convenience helper to get a logger with the ASE configuration applied."""
    return logging.getLogger(name if name is not None else __name__)


# Initialize logger for this module
configure_logging()
logger = get_logger(__name__)


# ===========================================================================
# RISK MODEL - Risk Scoring and Finding Creation
# ===========================================================================

def create_finding(
    *,
    id: str,
    title: str,
    category: str,
    description: str,
    recommendation: str,
    likelihood: int,
    impact: int,
    source: str,
) -> Finding:
    """Helper to create a Finding with computed raw_score and severity."""
    likelihood = max(1, min(3, likelihood))
    impact = max(1, min(3, impact))
    raw_score = likelihood * impact
    severity = _severity_from_raw(raw_score)
    finding = Finding(
        id=id,
        title=title,
        category=category,
        severity=severity,
        description=description,
        recommendation=recommendation,
        likelihood=likelihood,
        impact=impact,
        raw_score=raw_score,
        source=source,
    )
    logger.info("Finding created: %s (%s, raw=%d)", id, severity, raw_score)
    return finding


def _severity_from_raw(raw: int) -> str:
    if raw <= 2:
        return "Low"
    if raw <= 4:
        return "Medium"
    return "High"


def aggregate_risk(findings: List[Finding]) -> RiskSummary:
    """Aggregate findings into category scores and an overall score (0–10)."""
    if not findings:
        logger.info("No findings; returning baseline low risk summary.")
        return RiskSummary(
            overall_score=0.0,
            overall_severity="Low",
            category_scores=[],
        )

    cat_raw: Dict[str, int] = defaultdict(int)
    total_raw = 0
    for f in findings:
        cat_raw[f.category] += f.raw_score
        total_raw += f.raw_score

    logger.info("Total raw risk before normalization: %d", total_raw)

    max_considered = 40.0
    overall_score = min(10.0, (total_raw / max_considered) * 10.0)
    overall_severity = _severity_from_score(overall_score)

    category_scores: List[CategoryScore] = []
    for cat, raw in cat_raw.items():
        cat_score = min(10.0, (raw / max_considered) * 10.0)
        cat_sev = _severity_from_score(cat_score)
        category_scores.append(
            CategoryScore(category=cat, score=cat_score, severity=cat_sev)
        )

    logger.info(
        "Aggregate risk: overall_score=%.2f, severity=%s",
        overall_score,
        overall_severity,
    )

    return RiskSummary(
        overall_score=overall_score,
        overall_severity=overall_severity,
        category_scores=category_scores,
    )


def _severity_from_score(score: float) -> str:
    if score <= 3.0:
        return "Low"
    if score <= 7.0:
        return "Medium"
    return "High"


# ===========================================================================
# URL CHECKER - URL Security Analysis
# ===========================================================================

def perform_safe_url_check(url: str) -> Optional[URLScanResult]:
    """Perform a safe, non-intrusive GET request to inspect basic security aspects."""
    try:
        logger.info("Safe GET request started for %s", url)
        resp = requests.get(url, timeout=5, allow_redirects=True)
    except requests.RequestException as exc:
        logger.warning("URL check failed for %s: %s", url, exc)
        return None

    redirect_chain: List[str] = [url] + [h.url for h in resp.history]
    parsed = urlparse(resp.url)
    https = parsed.scheme.lower() == "https"

    result = URLScanResult(
        original_url=url,
        final_url=resp.url,
        https=https,
        status_code=resp.status_code,
        headers=dict(resp.headers),
        elapsed_ms=resp.elapsed.total_seconds() * 1000.0,
        redirect_chain=redirect_chain,
    )
    logger.info(
        "Safe GET request completed for %s with status %d and HTTPS=%s",
        url,
        resp.status_code,
        https,
    )
    return result


def analyze_url_security(scan: URLScanResult) -> List[Finding]:
    """Analyze response headers and connection properties and return URL findings."""
    findings: List[Finding] = []
    headers = {k.lower(): v for k, v in (scan.headers or {}).items()}

    # 1. HTTPS usage
    if not scan.https:
        findings.append(
            create_finding(
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
                likelihood=3,
                impact=3,
                source="url",
            )
        )

    # 2. HSTS
    sts = headers.get("strict-transport-security")
    if scan.https and not sts:
        findings.append(
            create_finding(
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
                likelihood=2,
                impact=2,
                source="url",
            )
        )

    # 3. Content Security Policy
    csp = headers.get("content-security-policy")
    if not csp:
        findings.append(
            create_finding(
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
            create_finding(
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
            create_finding(
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
            create_finding(
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
            create_finding(
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
            create_finding(
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
            create_finding(
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
            create_finding(
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


# ===========================================================================
# JSON ANALYZER - JSON Metadata Analysis
# ===========================================================================

def analyze_json_metadata(metadata: Dict[str, Any]) -> List[Finding]:
    """Analyze JSON metadata describing the application and security controls."""
    findings: List[Finding] = []

    app = metadata.get("app", {})
    auth = metadata.get("auth", {})
    apis = metadata.get("apis", [])
    database = metadata.get("database", {})
    security = metadata.get("security", {})

    if not app:
        logger.warning("JSON metadata missing 'app' section.")
    if not auth:
        logger.warning("JSON metadata missing 'auth' section.")
    if not database:
        logger.warning("JSON metadata missing 'database' section.")
    if not security:
        logger.warning("JSON metadata missing 'security' section.")

    # Transport & header-related configuration
    https_enabled = bool(security.get("https_enabled", False))
    if not https_enabled:
        findings.append(
            create_finding(
                id="JSON-HTTPS-001",
                title="HTTPS not enabled at application level",
                category="Data Protection & Transport",
                description=(
                    "The security metadata indicates that HTTPS is not enforced. "
                    "Unencrypted HTTP traffic exposes credentials and sensitive data "
                    "to interception and tampering."
                ),
                recommendation=(
                    "Enforce HTTPS for all environments (including staging) using "
                    "TLS certificates, and redirect HTTP to HTTPS. Consider enabling "
                    "HSTS once HTTPS is stable."
                ),
                likelihood=3,
                impact=3,
                source="json",
            )
        )

    hsts_enabled = bool(security.get("hsts_enabled", False))
    csp_configured = bool(security.get("csp_configured", False))
    centralized_validation = bool(security.get("centralized_input_validation", False))

    if https_enabled and not hsts_enabled:
        findings.append(
            create_finding(
                id="JSON-HTTPS-002",
                title="HSTS not enabled in configuration",
                category="Data Protection & Transport",
                description=(
                    "Metadata indicates HTTPS is used but HTTP Strict Transport Security "
                    "(HSTS) is not enabled. Without HSTS, browsers may still allow "
                    "downgrade to HTTP."
                ),
                recommendation=(
                    "Enable HSTS in your web server or framework configuration once "
                    "HTTPS is fully rolled out and tested."
                ),
                likelihood=2,
                impact=2,
                source="json",
            )
        )

    if not csp_configured:
        findings.append(
            create_finding(
                id="JSON-CSP-001",
                title="Content Security Policy not defined in metadata",
                category="Security Headers",
                description=(
                    "The security configuration does not indicate a Content Security "
                    "Policy. Without CSP, XSS and content injection issues are harder "
                    "to mitigate."
                ),
                recommendation=(
                    "Define a CSP at the application or reverse-proxy layer that "
                    "restricts script, style, and frame sources to trusted origins."
                ),
                likelihood=2,
                impact=2,
                source="json",
            )
        )

    # Authentication and password policy
    password_policy = auth.get("password_policy", {})
    mfa_enabled = bool(auth.get("mfa_enabled", False))
    min_length = int(password_policy.get("min_length", 0))
    requires_numbers = bool(password_policy.get("requires_numbers", False))
    requires_special = bool(password_policy.get("requires_special_chars", False))

    if min_length < 8:
        findings.append(
            create_finding(
                id="JSON-AUTH-001",
                title="Weak password length policy",
                category="Authentication & Session",
                description=(
                    f"Configured minimum password length is {min_length}, which is "
                    "below common best practices (often 10–12+ characters)."
                ),
                recommendation=(
                    "Increase minimum password length to at least 10–12 characters, "
                    "and encourage passphrases instead of short, complex strings."
                ),
                likelihood=2,
                impact=2,
                source="json",
            )
        )

    if not (requires_numbers and requires_special):
        findings.append(
            create_finding(
                id="JSON-AUTH-001B",
                title="Password complexity requirements are weak",
                category="Authentication & Session",
                description=(
                    "The password policy does not clearly require both numeric and "
                    "special characters. Weak complexity increases risk of guessing."
                ),
                recommendation=(
                    "Require a mix of character types or, preferably, adopt long "
                    "passphrases combined with breach password checks."
                ),
                likelihood=2,
                impact=2,
                source="json",
            )
        )

    if not mfa_enabled:
        findings.append(
            create_finding(
                id="JSON-AUTH-002",
                title="Multi-factor authentication (MFA) not enabled",
                category="Authentication & Session",
                description=(
                    "The metadata indicates MFA is not enabled for user accounts or "
                    "administrative access. This increases the risk of account takeover "
                    "through credential theft or guessing."
                ),
                recommendation=(
                    "Enable MFA for privileged users first (administrators, operators), "
                    "then roll out to general users. Support TOTP or WebAuthn where possible."
                ),
                likelihood=2,
                impact=3,
                source="json",
            )
        )

    rate_limit = auth.get("rate_limit_per_minute")
    lockout_threshold = auth.get("account_lockout_threshold")

    if rate_limit is None or rate_limit > 100:
        findings.append(
            create_finding(
                id="JSON-AUTH-003",
                title="Weak or missing login rate limiting",
                category="Authentication & Session",
                description=(
                    "Login endpoint appears to have weak or missing rate limiting, "
                    "which may allow brute-force or credential-stuffing attacks."
                ),
                recommendation=(
                    "Implement rate limiting and IP/user-based throttling on login and "
                    "password reset endpoints. Consider CAPTCHAs for suspicious patterns."
                ),
                likelihood=2,
                impact=2,
                source="json",
            )
        )

    if not lockout_threshold or lockout_threshold > 10:
        findings.append(
            create_finding(
                id="JSON-AUTH-004",
                title="High or missing account lockout threshold",
                category="Authentication & Session",
                description=(
                    "Account lockout threshold is high or undefined, increasing exposure "
                    "to online password guessing attacks."
                ),
                recommendation=(
                    "Introduce a reasonable lockout or step-up verification after several "
                    "failed attempts (e.g., 5–10), with cool-down windows and alerts."
                ),
                likelihood=2,
                impact=2,
                source="json",
            )
        )

    db_public = bool(database.get("public_network_access", False))
    uses_prepared = bool(database.get("uses_prepared_statements", False))
    uses_orm = bool(database.get("uses_orm", False))

    if db_public:
        findings.append(
            create_finding(
                id="JSON-DB-001",
                title="Database exposed to public network",
                category="Architecture & Configuration",
                description=(
                    "The database is marked as having public network access, which "
                    "increases attack surface and potential for direct DB attacks."
                ),
                recommendation=(
                    "Restrict database access to private networks or VPCs/VNETs. "
                    "Use application-layer access instead of direct public exposure."
                ),
                likelihood=2,
                impact=3,
                source="json",
            )
        )

    if not (uses_prepared or uses_orm):
        findings.append(
            create_finding(
                id="JSON-DB-002",
                title="Potential SQL injection risk (no prepared statements/ORM)",
                category="API Security",
                description=(
                    "Metadata suggests that neither prepared statements nor an ORM "
                    "are used consistently. This can increase the risk of SQL injection "
                    "if user input is concatenated into queries."
                ),
                recommendation=(
                    "Adopt parameterized queries or a well-reviewed ORM. "
                    "Avoid building SQL statements via string concatenation of user input."
                ),
                likelihood=2,
                impact=3,
                source="json",
            )
        )

    # Centralized input validation
    if not centralized_validation:
        findings.append(
            create_finding(
                id="JSON-VAL-001",
                title="No centralized input validation framework",
                category="Injection",
                description=(
                    "Security metadata does not indicate a centralized input validation "
                    "layer. Inconsistent validation across endpoints increases risk of "
                    "injection and data quality bugs."
                ),
                recommendation=(
                    "Introduce a shared validation layer or library and ensure all user "
                    "inputs are validated and normalized before use."
                ),
                likelihood=2,
                impact=2,
                source="json",
            )
        )

    if isinstance(apis, list) and apis:
        for api in apis:
            path = api.get("path", "")
            method = (api.get("method") or "GET").upper()
            auth_required = bool(api.get("auth_required", True))
            handles_sensitive = bool(api.get("handles_sensitive_data", False))
            rate_limit_ep = api.get("rate_limit_per_minute")

            if not auth_required and method in {"POST", "PUT", "DELETE", "PATCH"}:
                findings.append(
                    create_finding(
                        id=f"JSON-API-UNAUTH-{path}",
                        title="Unauthenticated state-changing API endpoint",
                        category="API Security",
                        description=(
                            f"API endpoint {method} {path} is marked as not requiring authentication, "
                            "which can be dangerous for state-changing operations."
                        ),
                        recommendation=(
                            "Require proper authentication and authorization for any API that changes "
                            "server-side state. Limit unauthenticated endpoints to safe reads."
                        ),
                        likelihood=2,
                        impact=3,
                        source="json",
                    )
                )

            if handles_sensitive and not auth_required:
                findings.append(
                    create_finding(
                        id=f"JSON-API-SENSITIVE-{path}",
                        title="Sensitive data exposed via unauthenticated API",
                        category="Data Protection & Transport",
                        description=(
                            f"API endpoint {path} is marked as handling sensitive data but does "
                            "not require authentication in the metadata."
                        ),
                        recommendation=(
                            "Restrict access to sensitive-data APIs with strong authentication and "
                            "role-based authorization. Avoid exposing such data anonymously."
                        ),
                        likelihood=3,
                        impact=3,
                        source="json",
                    )
                )

            if rate_limit_ep is None or rate_limit_ep > 1000:
                findings.append(
                    create_finding(
                        id=f"JSON-API-RL-{path}",
                        title="Weak or missing per-endpoint rate limiting",
                        category="API Security",
                        description=(
                            f"API endpoint {method} {path} appears to have high or undefined "
                            "rate limiting, which may allow abuse or resource exhaustion."
                        ),
                        recommendation=(
                            "Apply per-endpoint rate limits and quotas, with stricter limits "
                            "for sensitive or expensive operations."
                        ),
                        likelihood=2,
                        impact=2,
                        source="json",
                    )
                )

    logger.info("JSON metadata analysis produced %d findings", len(findings))
    return findings


# ===========================================================================
# ATTACK SIMULATOR - Simulated Attack Scenarios
# ===========================================================================

def run_all_simulations(
    metadata: Dict[str, Any],
    url_result: URLScanResult,
) -> List[Finding]:
    """Run all conceptual, rule-based simulations using metadata + URL scan result."""
    findings: List[Finding] = []
    findings.extend(_simulate_sql_injection(metadata))
    findings.extend(_simulate_auth_weakness(metadata))
    findings.extend(_simulate_directory_exposure(metadata, url_result))
    findings.extend(_simulate_api_misuse(metadata))
    findings.extend(_simulate_performance(metadata, url_result))

    logger.info("Attack simulations produced %d findings", len(findings))
    return findings


def _simulate_sql_injection(metadata: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    database = metadata.get("database", {})
    security = metadata.get("security", {})

    uses_prepared = bool(database.get("uses_prepared_statements", False))
    uses_orm = bool(database.get("uses_orm", False))
    centralized_validation = bool(security.get("centralized_input_validation", False))

    if not (uses_prepared or uses_orm) and not centralized_validation:
        findings.append(
            create_finding(
                id="SIM-SQLI-001",
                title="Simulated SQL injection risk (no prepared statements/ORM and weak validation)",
                category="Injection",
                description=(
                    "Based on the metadata, the application does not clearly use prepared "
                    "statements or an ORM, and there is no strong centralized input "
                    "validation. An attacker *could* attempt SQL injection in inputs that "
                    "reach the database, especially search fields, login forms, or filters."
                ),
                recommendation=(
                    "Introduce parameterized queries or an ORM, and validate/encode all user "
                    "input before it reaches the database layer. Add security tests for "
                    "injection-prone endpoints."
                ),
                likelihood=3,
                impact=3,
                source="simulation",
            )
        )

    return findings


def _simulate_auth_weakness(metadata: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    auth = metadata.get("auth", {})

    mfa_enabled = bool(auth.get("mfa_enabled", False))
    session_timeout_minutes = int(auth.get("session_timeout_minutes", 0) or 0)
    remember_me_days = int(auth.get("remember_me_days", 0) or 0)

    if not mfa_enabled:
        findings.append(
            create_finding(
                id="SIM-AUTH-001",
                title="Simulated credential stuffing risk (no MFA)",
                category="Authentication & Session",
                description=(
                    "Without MFA, stolen or guessed credentials would likely allow "
                    "direct account takeover. Attackers commonly use credential "
                    "stuffing against login endpoints."
                ),
                recommendation=(
                    "Roll out MFA for high-value accounts. Monitor login events for "
                    "suspicious activity and enforce strong passwords."
                ),
                likelihood=3,
                impact=3,
                source="simulation",
            )
        )

    if session_timeout_minutes and session_timeout_minutes > 60:
        findings.append(
            create_finding(
                id="SIM-AUTH-002",
                title="Simulated session hijacking window (long session timeout)",
                category="Authentication & Session",
                description=(
                    "Sessions appear to last longer than one hour, increasing the window "
                    "for session theft or misuse if tokens are exposed."
                ),
                recommendation=(
                    "Shorten session lifetime or use idle timeouts for sensitive areas. "
                    "Implement secure cookie flags and consider device binding or token "
                    "revocation on logout."
                ),
                likelihood=2,
                impact=2,
                source="simulation",
            )
        )

    if remember_me_days and remember_me_days > 30:
        findings.append(
            create_finding(
                id="SIM-AUTH-003",
                title="Simulated persistent token abuse (long-lived remember-me)",
                category="Authentication & Session",
                description=(
                    "Very long 'remember-me' durations increase risk if devices are shared "
                    "or lost, as tokens may remain valid for weeks or months."
                ),
                recommendation=(
                    "Limit remember-me durations, tie tokens to devices, and support remote "
                    "session revocation from the user profile."
                ),
                likelihood=2,
                impact=2,
                source="simulation",
            )
        )

    return findings


def _simulate_directory_exposure(
    metadata: Dict[str, Any],
    url_result: URLScanResult,
) -> List[Finding]:
    findings: List[Finding] = []

    security = metadata.get("security", {})
    interesting_paths = security.get("interesting_paths", [])

    if interesting_paths:
        findings.append(
            create_finding(
                id="SIM-DIR-001",
                title="Potential directory exposure risk (sensitive paths declared)",
                category="Security Misconfiguration",
                description=(
                    "Metadata lists potentially sensitive paths, such as admin panels or "
                    "backup directories. If these are not properly authenticated or "
                    "restricted, an attacker *could* discover and access them."
                ),
                recommendation=(
                    "Ensure that all sensitive paths are protected by strong authentication "
                    "and authorization. Disable directory listing and avoid placing raw "
                    "backups in web-accessible locations."
                ),
                likelihood=2,
                impact=2,
                source="simulation",
            )
        )

    return findings


def _simulate_api_misuse(metadata: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    apis = metadata.get("apis", [])

    for api in apis or []:
        path = api.get("path", "")
        method = (api.get("method") or "GET").upper()
        auth_required = bool(api.get("auth_required", True))
        handles_sensitive = bool(api.get("handles_sensitive_data", False))

        if method == "GET" and not auth_required and handles_sensitive:
            findings.append(
                create_finding(
                    id=f"SIM-API-001-{path}",
                    title="Simulated data scraping via unauthenticated API",
                    category="API Security",
                    description=(
                        f"Endpoint {method} {path} is unauthenticated but marked as handling "
                        "sensitive data. An attacker could script large-scale scraping or "
                        "enumeration of that data."
                    ),
                    recommendation=(
                        "Require authentication and authorization for sensitive data APIs. "
                        "Add rate limiting and anomaly detection for unusual access patterns."
                    ),
                    likelihood=3,
                    impact=3,
                    source="simulation",
                )
            )

    return findings


def _simulate_performance(
    metadata: Dict[str, Any],
    url_result: URLScanResult,
) -> List[Finding]:
    findings: List[Finding] = []

    perf_meta = metadata.get("performance", {})
    expected_rps = int(perf_meta.get("expected_requests_per_second", 0) or 0)
    elapsed_ms = url_result.elapsed_ms

    if elapsed_ms > 1500 and expected_rps > 100:
        findings.append(
            create_finding(
                id="SIM-PERF-001",
                title="Simulated performance risk under peak load",
                category="Operations & Monitoring",
                description=(
                    "The observed response time for a single request is relatively high "
                    f"({elapsed_ms:.0f} ms), while the metadata suggests high expected load "
                    f"({expected_rps} requests/second). Under stress, the application may "
                    "experience timeouts or degradation."
                ),
                recommendation=(
                    "Consider load testing in a controlled environment, adding caching, "
                    "and optimizing slow endpoints. Introduce rate limiting and circuit "
                    "breakers to protect core services."
                ),
                likelihood=2,
                impact=2,
                source="simulation",
            )
        )

    return findings


# ===========================================================================
# REPORT GENERATOR - Text Report Generation
# ===========================================================================

def build_text_report(
    *,
    metadata: Dict[str, Any],
    url_result: Optional[URLScanResult],
    summary: RiskSummary,
    findings: List[Finding],
) -> str:
    """Build a developer-friendly, text-only report."""
    logger.info("Building text report with %d findings", len(findings))

    lines: List[str] = []

    app_name = (metadata.get("app") or {}).get("name", "Unknown Application")
    lines.append("============================================================")
    lines.append("       ATTACK SIMULATION ENGINE (ASE) – SECURITY REPORT")
    lines.append("============================================================")
    lines.append(f"Application: {app_name}")
    lines.append("Generated by: ASE (Internal Developer Tool)")
    lines.append("Note: All checks are heuristic and non-intrusive.")
    lines.append("Use only on systems you own or are authorized to test.")
    lines.append("")
    
    lines.append("------------------------------------------------------------")
    lines.append("1. EXECUTIVE SUMMARY")
    lines.append("------------------------------------------------------------")
    lines.append(
        f"Overall Risk Score: {summary.overall_score:.1f} / 10 "
        f"[{summary.overall_severity.upper()}]"
    )
    lines.append("")
    lines.append("Category Risk Overview:")
    for cs in summary.category_scores:
        lines.append(
            f"  * {cs.category:<30} : {cs.score:.1f} / 10 ({cs.severity})"
        )
    lines.append("")

    lines.append("------------------------------------------------------------")
    lines.append("2. APPLICATION OVERVIEW")
    lines.append("------------------------------------------------------------")
    app = metadata.get("app", {})
    env = app.get("environment", "N/A")
    stack = app.get("stack", {})
    backend = stack.get("backend", "N/A")
    frontend = stack.get("frontend", "N/A")
    framework = stack.get("framework", "N/A")
    lines.append(f"Environment : {env}")
    lines.append(f"Backend     : {backend}")
    lines.append(f"Frontend    : {frontend}")
    lines.append(f"Framework   : {framework}")
    lines.append("")

    if url_result is not None:
        lines.append(f"Target URL            : {url_result.original_url}")
        lines.append(f"Final URL             : {url_result.final_url}")
        lines.append(f"Status Code           : {url_result.status_code}")
        lines.append(f"HTTPS Enabled         : {'Yes' if url_result.https else 'No'}")
        lines.append(f"Approx. Response Time : {url_result.elapsed_ms:.0f} ms")
        lines.append("")

    lines.append("------------------------------------------------------------")
    lines.append("3. DETAILED FINDINGS")
    lines.append("------------------------------------------------------------")
    if not findings:
        lines.append("No findings were generated.")
    else:
        for idx, f in enumerate(findings, start=1):
            lines.append(f"Finding #{idx}: {f.title}")
            lines.append(f"Severity: {f.severity.upper()} | ID: {f.id}")
            lines.append(f"Category: {f.category}")
            lines.append(f"Source  : {f.source}")
            lines.append(
                f"Risk    : {f.likelihood} (Likelihood) x {f.impact} (Impact) = {f.raw_score}"
            )
            lines.append(f"Description:\n  {f.description}")
            lines.append(f"Recommendation:\n  {f.recommendation}")
            lines.append("-" * 60)
            lines.append("")

    lines.append("------------------------------------------------------------")
    lines.append("4. SIMULATED ATTACK SCENARIOS (HEURISTIC)")
    lines.append("------------------------------------------------------------")
    lines.append(
        "The following scenarios are **simulated** based on metadata and headers only. "
        "No real exploitation was performed."
    )
    lines.append("")
    sim_findings = [f for f in findings if f.source == "simulation"]
    if not sim_findings:
        lines.append("No simulation-specific findings were generated.")
    else:
        for f in sim_findings:
             lines.append(f"- {f.title} ({f.category}, {f.severity})")
    lines.append("")

    lines.append("------------------------------------------------------------")
    lines.append("5. RECOMMENDED NEXT STEPS")
    lines.append("------------------------------------------------------------")
    lines.append(
        "1) Address High and Medium severity findings starting with Authentication, "
        "Data Protection, and API Security."
    )
    lines.append(
        "2) Introduce automated security testing (SAST/DAST) and security linters "
        "in your CI/CD pipeline."
    )
    lines.append(
        "3) Periodically review logs and implement centralized monitoring for "
        "suspicious activity."
    )
    lines.append(
        "4) Consider a dedicated, authorized penetration test for critical systems, "
        "complementing this heuristic tool."
    )
    lines.append("")
    lines.append("============================================================")
    lines.append("                   END OF REPORT")
    lines.append("============================================================")

    return "\n".join(lines)


# ===========================================================================
# STREAMLIT UI - Main Application Interface
# ===========================================================================

def init_session_state() -> None:
    """Initialise all Streamlit session‑state keys used throughout the app."""
    defaults = {
        "json_metadata": None,
        "json_findings": [],
        "url_result": None,
        "url_findings": [],
        "simulation_findings": [],
        "risk_summary": None,
        "combined_findings": [],
        "light_mode": False,
        "chat_history": [],
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def inject_custom_css(light_mode: bool = False) -> None:
    """Inject CSS into the Streamlit app."""
    st.markdown(
        """
        <link href='https://fonts.googleapis.com/icon?family=Material+Icons' rel='stylesheet'>
        """,
        unsafe_allow_html=True,
    )

    if light_mode:
        css = """
        <style>
        .stApp {background-color: #ffffff; color: #1a1a1a; font-family: 'Inter', sans-serif;}
        h1, h2, h3, h4, h5, h6 {color: #003366 !important; font-weight: 700;}
        [data-testid='stSidebar'] {background-color: #f5f5f5; border-right: 1px solid #ccc;}
        [data-testid='stSidebar'] h1, [data-testid='stSidebar'] h2, [data-testid='stSidebar'] h3 {color: #003366 !important;}
        [data-testid='stSidebar'] p, [data-testid='stSidebar'] span, [data-testid='stSidebar'] label, [data-testid='stSidebar'] div {color: #1a1a1a !important;}
        .stButton > button {background: linear-gradient(45deg, #0066ff, #33ccff); color: white; border: none; border-radius: 8px; font-weight: 600; transition: all 0.3s ease;}
        .stButton > button:hover {transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,102,255,0.3);}
        .stJson {background-color: #1e1e1e !important;}
        .stJson pre {color: #ffffff !important; background-color: #1e1e1e !important;}
        p, span, label, div, li {color: #1a1a1a !important;}
        </style>
        """
    else:
        css = """
        <style>
        .stApp {background-color: #0e1117; font-family: 'Inter', sans-serif;}
        h1, h2, h3 {color: #00ffcc !important; font-weight: 700;}
        [data-testid='stSidebar'] {background-color: #161b22; border-right: 1px solid #30363d;}
        [data-testid='stSidebar'] h1, [data-testid='stSidebar'] h2, [data-testid='stSidebar'] h3 {color: #00ffcc !important;}
        [data-testid='stSidebar'] p, [data-testid='stSidebar'] span, [data-testid='stSidebar'] label, [data-testid='stSidebar'] div {color: #ffffff !important;}
        .stButton > button {background: linear-gradient(45deg, #00d2ff, #3a7bd5); color: white; border: none; border-radius: 8px; font-weight: 600; transition: all 0.3s ease;}
        .stButton > button:hover {transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,210,255,0.3);}
        p, span, label, div, li {color: #e6edf3;}
        </style>
        """
    st.markdown(css, unsafe_allow_html=True)


def get_chatbot_response(user_message: str, findings_context: str = "") -> str:
    """Get AI-powered security suggestions using Google Generative AI."""
    if genai is None:
        return "⚠️ Chatbot feature requires 'google-generativeai' package."
    
    try:
        genai.configure(api_key="AIzaSyB4KJj2K6WlSPmmAWe34oVdZJuIlg6PY9M")
        model = genai.GenerativeModel('gemini-1.5-flash-latest')
        
        system_context = """You are a cybersecurity expert assistant for the Attack Simulation Engine (ASE). 
        Your role is to provide helpful security suggestions, explain findings, and answer questions about web security.
        Be concise, practical, and focus on actionable advice."""
        
        full_prompt = f"{system_context}\n\n"
        if findings_context:
            full_prompt += f"Current Security Findings:\n{findings_context}\n\n"
        full_prompt += f"User Question: {user_message}"
        
        response = model.generate_content(full_prompt)
        return response.text
    except Exception as e:
        logger.error(f"Chatbot error: {e}")
        return f"❌ Error getting response: {str(e)}"


def export_findings_csv(findings: List[Finding]) -> str:
    """Return a CSV string for the supplied findings list."""
    if not findings:
        return ""
    df = pd.DataFrame([
        {
            "ID": f.id,
            "Title": f.title,
            "Category": f.category,
            "Severity": f.severity,
            "Source": f.source,
            "Likelihood": f.likelihood,
            "Impact": f.impact,
            "Raw Risk": f.raw_score,
        }
        for f in findings
    ])
    return df.to_csv(index=False)


def render_score_summary(summary: RiskSummary) -> None:
    severity_color = {
        "Low": "green",
        "Medium": "orange",
        "High": "red",
    }.get(summary.overall_severity, "gray")
    st.markdown(
        f"**Overall Risk Score:** "
        f"<span style='color:{severity_color};font-size:1.4em;'>{summary.overall_score:.1f} / 10 ({summary.overall_severity})</span>",
        unsafe_allow_html=True,
    )
    st.markdown("**Category Scores:**")
    categories = [cs.category for cs in summary.category_scores]
    scores = [cs.score for cs in summary.category_scores]
    if px:
        df = pd.DataFrame({"Category": categories, "Score": scores})
        fig = px.bar(df, x="Category", y="Score", color_discrete_sequence=["#00ffcc"])
        st.plotly_chart(fig, use_container_width=True)
    else:
        chart_data = {"Category": categories, "Score": scores}
        st.bar_chart(chart_data, x="Category", y="Score", color="#00ffcc")
    for cat_score in summary.category_scores:
        color = {
            "Low": "green",
            "Medium": "orange",
            "High": "red",
        }.get(cat_score.severity, "gray")
        st.markdown(
            f"- **{cat_score.category}**: "
            f"<span style='color:{color};'>{cat_score.score:.1f} / 10 ({cat_score.severity})</span>",
            unsafe_allow_html=True,
        )


def render_findings_table(findings: List[Finding]) -> None:
    if not findings:
        st.info("No findings to display.")
        return
    data = []
    for f in findings:
        data.append(
            {
                "ID": f.id,
                "Title": f.title,
                "Category": f.category,
                "Severity": f.severity,
                "Source": f.source,
                "Likelihood": f.likelihood,
                "Impact": f.impact,
                "Raw Risk": f.raw_score,
            }
        )
    df = pd.DataFrame(data)
    st.dataframe(df, use_container_width=True)


def render_findings_and_score(
    findings: List[Finding],
    summary: RiskSummary,
    is_partial: bool = False,
) -> None:
    if is_partial:
        st.markdown("**Note:** Score shown is based on current findings subset.")
    render_score_summary(summary)
    render_findings_table(findings)


def run_json_analysis_view() -> None:
    st.header("📄 JSON‑Based Application Analysis")
    uploaded_file = st.file_uploader(
        "Upload JSON metadata file",
        type=["json"],
        help="Upload your architecture & security metadata.",
    )
    if uploaded_file is not None:
        try:
            metadata = json.load(uploaded_file)
            st.session_state["json_metadata"] = metadata
            logger.info("JSON file uploaded")
            st.success("JSON file loaded successfully.")
            st.json(metadata)
        except json.JSONDecodeError as exc:
            logger.warning("Failed to parse JSON file: %s", exc)
            st.error("Invalid JSON file. Please check the file content.")
            return

    if st.button("Run JSON Analysis"):
        if not st.session_state.get("json_metadata"):
            st.warning("Please upload a JSON metadata file first.")
            return
        with st.spinner("Analyzing JSON metadata…"):
            logger.info("JSON metadata analysis started")
            findings: List[Finding] = analyze_json_metadata(
                st.session_state["json_metadata"]
            )
            st.session_state["json_findings"] = findings
            summary: RiskSummary = aggregate_risk(findings)
            st.session_state["risk_summary"] = summary
            st.session_state["combined_findings"] = findings
            logger.info("Risk scoring completed (JSON‑only)")
        render_findings_and_score(findings, summary)
        csv_data = export_findings_csv(findings)
        if csv_data:
            st.download_button(
                label="Download JSON Findings (CSV)",
                data=csv_data,
                file_name="json_findings.csv",
                mime="text/csv",
            )


def run_url_and_simulation_view() -> None:
    st.header("🌐 Safe URL Check & Attack Simulation (Safe Mode)")
    url = st.text_input(
        "Target URL (only your own website):",
        placeholder="https://example.com",
    )
    ownership_ack = st.checkbox(
        "I confirm I own or am authorized to test this URL.",
        value=False,
    )
    if st.button("Start Scan (URL & Simulation)"):
        if not url:
            st.warning("Please enter a URL first.")
            return
        if not ownership_ack:
            st.warning("You must confirm ownership/authorization before scanning.")
            return
        with st.spinner("Performing safe URL check…"):
            logger.info("Safe URL check initiated for %s", url)
            url_result: Optional[URLScanResult] = perform_safe_url_check(url)
            st.session_state["url_result"] = url_result
            if url_result is None:
                st.error("URL check failed. See logs for details.")
                return
        st.subheader("🔎 Safe URL Check Results")
        st.write(f"**Final URL:** {url_result.final_url}")
        st.write(f"**Status code:** {url_result.status_code}")
        st.write(f"**HTTPS enabled:** {'Yes' if url_result.https else 'No'}")
        st.write("**Response headers:**")
        st.json(url_result.headers)
        with st.spinner("Analyzing URL security…"):
            url_findings: List[Finding] = analyze_url_security(url_result)
            st.session_state["url_findings"] = url_findings
        if url_findings:
            st.subheader("🔐 URL Security Findings")
            render_findings_table(url_findings)
        with st.spinner("Running attack simulations…"):
            logger.info("Attack simulations started")
            metadata: Dict[str, Any] = st.session_state.get("json_metadata") or {}
            simulation_findings: List[Finding] = run_all_simulations(
                metadata, url_result
            )
            st.session_state["simulation_findings"] = simulation_findings
        combined_findings: List[Finding] = (
            list(st.session_state.get("json_findings") or [])
            + url_findings
            + simulation_findings
        )
        st.session_state["combined_findings"] = combined_findings
        summary: RiskSummary = aggregate_risk(combined_findings)
        st.session_state["risk_summary"] = summary
        st.subheader("⚔️ Simulated Attack Scenarios (Heuristic Only)")
        render_findings_and_score(simulation_findings, summary, is_partial=True)
        csv_data = export_findings_csv(simulation_findings)
        if csv_data:
            st.download_button(
                label="Download Simulation Findings (CSV)",
                data=csv_data,
                file_name="simulation_findings.csv",
                mime="text/csv",
            )


def run_combined_report_view() -> None:
    st.header("📋 Combined Security Report")
    findings: List[Finding] = st.session_state.get("combined_findings") or []
    summary: Optional[RiskSummary] = st.session_state.get("risk_summary")
    metadata: Dict[str, Any] = st.session_state.get("json_metadata") or {}
    url_result: Optional[URLScanResult] = st.session_state.get("url_result")
    if not findings or summary is None:
        st.info("Run the JSON Analysis and/or URL & Simulation first to build a report.")
        return
    with st.spinner("Generating report…"):
        logger.info("Report generation started")
        report_text = build_text_report(
            metadata=metadata,
            url_result=url_result,
            summary=summary,
            findings=findings,
        )
        logger.info("Report assembled for display")
    st.subheader("🧭 Summary")
    render_score_summary(summary)
    st.subheader("🔎 Detailed Findings")
    render_findings_table(findings)
    st.subheader("📝 Full Text Report")
    st.text_area(
        "Report (copy or download as needed):",
        value=report_text,
        height=400,
    )
    st.download_button(
        "Download Report as .txt",
        data=report_text,
        file_name="ase_security_report.txt",
        mime="text/plain",
    )
    if FPDF is not None:
        if st.button("Generate PDF Report"):
            with st.spinner("Creating PDF…"):
                pdf = FPDF()
                pdf.add_page()
                pdf.set_auto_page_break(auto=True, margin=15)
                pdf.set_font("Helvetica", size=12)
                for line in report_text.splitlines():
                    pdf.multi_cell(0, 10, txt=line)
                pdf_bytes = pdf.output(dest="S").encode("latin1")
                st.download_button(
                    "Download Report as .pdf",
                    data=pdf_bytes,
                    file_name="ase_security_report.pdf",
                    mime="application/pdf",
                )


def run_ai_chat_view() -> None:
    st.header("🤖 AI Security Assistant")
    st.markdown("Ask me anything about security findings, vulnerabilities, or best practices!")
    
    findings_context = ""
    if st.session_state.get("combined_findings"):
        findings_list = st.session_state["combined_findings"][:5]
        findings_context = "\n".join([f"- {f.title} ({f.severity})" for f in findings_list])
        
        with st.expander("📊 Current Findings Context"):
            st.write("The AI has access to your current security findings:")
            for f in findings_list:
                st.write(f"• **{f.title}** - {f.severity}")
    
    st.markdown("### 💬 Conversation")
    chat_container = st.container()
    
    with chat_container:
        if st.session_state.get("chat_history"):
            for i, chat in enumerate(st.session_state["chat_history"]):
                st.markdown(f"""
                <div style="background-color: {'#e3f2fd' if not st.session_state['light_mode'] else '#0066ff'}; 
                            padding: 10px; border-radius: 10px; margin: 10px 0; 
                            color: {'#000' if st.session_state['light_mode'] else '#fff'};">
                    <strong>👤 You:</strong> {chat['user']}
                </div>
                """, unsafe_allow_html=True)
                
                st.markdown(f"""
                <div style="background-color: {'#f5f5f5' if st.session_state['light_mode'] else '#1e1e1e'}; 
                            padding: 10px; border-radius: 10px; margin: 10px 0;
                            color: {'#000' if st.session_state['light_mode'] else '#fff'};">
                    <strong>🤖 Assistant:</strong><br>{chat['bot']}
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("👋 Start a conversation by typing a message below!")
    
    st.markdown("---")
    col1, col2 = st.columns([5, 1])
    
    with col1:
        user_message = st.text_input(
            "Type your message...",
            placeholder="e.g., How can I fix the HTTPS issues found?",
            key="chat_input",
            label_visibility="collapsed"
        )
    
    with col2:
        send_button = st.button("Send 📤", use_container_width=True)
    
    if send_button and user_message:
        with st.spinner("🤔 Thinking..."):
            response = get_chatbot_response(user_message, findings_context)
            st.session_state["chat_history"].append({
                "user": user_message,
                "bot": response
            })
        st.rerun()
    
    if st.session_state.get("chat_history"):
        if st.button("🗑️ Clear Chat History"):
            st.session_state["chat_history"] = []
            st.rerun()


def main() -> None:
    st.set_page_config(
        page_title="Attack Simulation Engine (ASE)",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    init_session_state()
    with st.sidebar:
        st.title("🛡️ ASE")
        st.caption("Internal Security Auditor")
        st.markdown("---")
        light_mode = st.checkbox("Light mode", value=st.session_state["light_mode"], key="light_mode_toggle")
        st.session_state["light_mode"] = light_mode
        view = st.radio(
            "Navigation",
            options=["JSON Analysis", "URL & Simulation", "Combined Report", "🤖 Assistant Chat"],
            index=0,
        )
        st.markdown("---")
        st.info(
            "**Note:** ASE performs heuristic, non‑exploitative checks only. "
            "Use it only on systems you own."
        )
    
    inject_custom_css(light_mode=st.session_state["light_mode"])
    if view == "JSON Analysis":
        run_json_analysis_view()
    elif view == "URL & Simulation":
        run_url_and_simulation_view()
    elif view == "Combined Report":
        run_combined_report_view()
    elif view == "🤖 Assistant Chat":
        run_ai_chat_view()


if __name__ == "__main__":
    main()

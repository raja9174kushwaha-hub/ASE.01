from typing import Any, Dict, List

from logging_utils import get_logger
from models import Finding
import risk_model


logger = get_logger(__name__)


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

    # --- Transport & header-related configuration ---
    https_enabled = bool(security.get("https_enabled", False))
    if not https_enabled:
        findings.append(
            risk_model.create_finding(
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
                likelihood=5,
                impact=5,
                source="json",
            )
        )

    hsts_enabled = bool(security.get("hsts_enabled", False))
    csp_configured = bool(security.get("csp_configured", False))
    centralized_validation = bool(security.get("centralized_input_validation", False))

    if https_enabled and not hsts_enabled:
        findings.append(
            risk_model.create_finding(
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
            risk_model.create_finding(
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

    # --- Authentication and password policy ---
    password_policy = auth.get("password_policy", {})
    mfa_enabled = bool(auth.get("mfa_enabled", False))
    min_length = int(password_policy.get("min_length", 0))
    requires_numbers = bool(password_policy.get("requires_numbers", False))
    requires_special = bool(password_policy.get("requires_special_chars", False))

    if min_length < 8:
        findings.append(
            risk_model.create_finding(
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
            risk_model.create_finding(
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
            risk_model.create_finding(
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
                likelihood=4,
                impact=4,
                source="json",
            )
        )

    rate_limit = auth.get("rate_limit_per_minute")
    lockout_threshold = auth.get("account_lockout_threshold")

    if rate_limit is None or rate_limit > 100:
        findings.append(
            risk_model.create_finding(
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
            risk_model.create_finding(
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

    session_timeout_minutes = int(auth.get("session_timeout_minutes", 0) or 0)
    remember_me_days = int(auth.get("remember_me_days", 0) or 0)

    if session_timeout_minutes == 0 or session_timeout_minutes > 60:
        findings.append(
            risk_model.create_finding(
                id="JSON-SESS-001",
                title="Weak or missing session timeout policy",
                category="Authentication & Session",
                description=(
                    f"Session timeout is set to {session_timeout_minutes} minutes. "
                    "Long or infinite sessions increase the risk of session hijacking."
                ),
                recommendation=(
                    "Configure a reasonable absolute session timeout (e.g., 30-60 minutes) "
                    "and an idle timeout to reduce exposure."
                ),
                likelihood=3,
                impact=3,
                source="json",
            )
        )

    if remember_me_days > 14:
        findings.append(
            risk_model.create_finding(
                id="JSON-SESS-002",
                title="Excessive 'Remember Me' duration",
                category="Authentication & Session",
                description=(
                    f"Remember Me functionality is set to {remember_me_days} days. "
                    "Long-lived persistent sessions can bypass MFA and increase theft windows."
                ),
                recommendation=(
                    "Limit 'Remember Me' to a shorter period (e.g., 7-14 days) or verify "
                    "critical actions with a fresh login/MFA."
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
            risk_model.create_finding(
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
                likelihood=4,
                impact=5,
                source="json",
            )
        )

    if not (uses_prepared or uses_orm):
        findings.append(
            risk_model.create_finding(
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
                likelihood=4,
                impact=5,
                source="json",
            )
        )

    # Centralized input validation
    if not centralized_validation:
        findings.append(
            risk_model.create_finding(
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
                    risk_model.create_finding(
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
                    risk_model.create_finding(
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
                        likelihood=5,
                        impact=4,
                        source="json",
                    )
                )

            if rate_limit_ep is None or rate_limit_ep > 1000:
                findings.append(
                    risk_model.create_finding(
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

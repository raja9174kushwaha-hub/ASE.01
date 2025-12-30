"""
Session State Manager for ASE

Handles:
1. Initialization of session state
2. Clearing stale scan data between new scans
3. Managing scan result lifecycle
4. Preventing data mixing between different scan types
"""

import logging
from logging_utils import get_logger

logger = get_logger(__name__)

def init_session_state(st) -> None:
    """Initialize all Streamlit session state keys used throughout the app."""
    defaults = {
        # User & Auth
        "current_user": None,  # {name, email, org, role}
        "registered_users": {},
        "auth_mode": "login",
        
        # Scan results (cleared on new scan)
        "last_scan_type": None,  # "url_scan", "nmap_scan", "json_scan", "code_scan"
        "url_result": None,
        "url_findings": [],
        "json_metadata": None,
        "json_findings": [],
        "nmap_findings": [],
        "code_findings": [],
        "combined_findings": [],  # Aggregated from all active scans
        
        # Risk summary
        "risk_summary": None,
        
        # UI state
        "light_mode": False,
        "chat_history": [],
        "show_loading": False,
        "last_error": None,
        
        # Audit & Security
        "scan_audit_log": [],
        "security_incidents": [],
    }
    
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value
            logger.debug("Initialized session state key: %s", key)


def clear_scan_results(st, exclude_types: list = None) -> None:
    """
    Clear scan results to prevent mixing with previous scans.
    
    Args:
        st: Streamlit session state
        exclude_types: List of scan types to NOT clear (e.g., don't clear JSON if user wants to keep it)
    """
    if exclude_types is None:
        exclude_types = []
    
    to_clear = {
        "url_result": "url_scan" not in exclude_types,
        "url_findings": "url_scan" not in exclude_types,
        "nmap_findings": "nmap_scan" not in exclude_types,
        "json_findings": "json_scan" not in exclude_types,
        "code_findings": "code_scan" not in exclude_types,
        "combined_findings": True,  # Always reset combined
        "risk_summary": True,
        "last_error": True,
    }
    
    for key, should_clear in to_clear.items():
        if should_clear:
            st.session_state[key] = [] if "findings" in key else None
            logger.info("Cleared session state: %s", key)


def add_finding_to_combined(st, finding) -> None:
    """Add a finding to combined_findings (deduplicates by finding ID)."""
    if not st.session_state.get("combined_findings"):
        st.session_state["combined_findings"] = []
    
    # Check if finding already exists by ID
    existing_ids = {f.id for f in st.session_state["combined_findings"]}
    if finding.id not in existing_ids:
        st.session_state["combined_findings"].append(finding)
        logger.debug("Added finding to combined: %s", finding.id)
    else:
        logger.debug("Skipped duplicate finding: %s", finding.id)


def set_last_error(st, error_message: str) -> None:
    """Set last error message for display."""
    st.session_state["last_error"] = error_message
    logger.warning("Session error set: %s", error_message)


def clear_last_error(st) -> None:
    """Clear error message."""
    st.session_state["last_error"] = None


def get_last_error(st) -> str:
    """Get last error message or empty string."""
    return st.session_state.get("last_error") or ""


def is_scan_in_progress(st) -> bool:
    """Check if a scan is currently in progress."""
    return st.session_state.get("show_loading", False)


def set_scan_in_progress(st, in_progress: bool) -> None:
    """Set scan progress indicator."""
    st.session_state["show_loading"] = in_progress
    logger.debug("Scan progress set to: %s", in_progress)


def get_current_user(st) -> dict:
    """Get current logged-in user or None."""
    return st.session_state.get("current_user")


def is_user_authenticated(st) -> bool:
    """Check if user is logged in."""
    return st.session_state.get("current_user") is not None

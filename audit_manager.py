
import json
import logging
import os
import datetime
from threading import Lock

logger = logging.getLogger(__name__)

AUDIT_DB_FILE = "audit_log.json"
_audit_lock = Lock()

def log_event(user_email: str, event_type: str, details: dict = None) -> None:
    """Logs a user event to the persistent audit file."""
    if details is None:
        details = {}
    
    event = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "user_email": user_email,
        "event_type": event_type,
        "details": details
    }
    
    # Load existing logs to append
    # In a real database, we would just INSERT. Here we read-modify-write.
    existing_logs = get_all_logs()
    existing_logs.append(event)
    
    with _audit_lock:
        try:
            with open(AUDIT_DB_FILE, "w") as f:
                json.dump(existing_logs, f, indent=2)
        except OSError as e:
            logger.error(f"Failed to save audit log: {e}")

def get_all_logs() -> list:
    """Retrieves all audit logs."""
    if not os.path.exists(AUDIT_DB_FILE):
        return []
    
    with _audit_lock:
        try:
            with open(AUDIT_DB_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"Failed to load audit logs: {e}")
            return []


import json
import logging
import os
from threading import Lock

logger = logging.getLogger(__name__)

# File to store user data
USERS_DB_FILE = "users_db.json"
_file_lock = Lock()

def load_users_from_file() -> dict:
    """Load registered users from local JSON file."""
    if not os.path.exists(USERS_DB_FILE):
        return {}
    
    with _file_lock:
        try:
            with open(USERS_DB_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"Failed to load users database: {e}")
            return {}

def save_users_to_file(users: dict) -> None:
    """Save registered users to local JSON file."""
    with _file_lock:
        try:
            with open(USERS_DB_FILE, "w") as f:
                json.dump(users, f, indent=2)
        except OSError as e:
            logger.error(f"Failed to save users database: {e}")

def delete_user(email: str) -> bool:
    """Deletes a user from the persistent store. Returns True if successful."""
    with _file_lock:
        try:
            if not os.path.exists(USERS_DB_FILE):
                return False
            
            with open(USERS_DB_FILE, "r") as f:
                users = json.load(f)
            
            if email in users:
                del users[email]
                
                with open(USERS_DB_FILE, "w") as f:
                    json.dump(users, f, indent=2)
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to delete user {email}: {e}")
            return False

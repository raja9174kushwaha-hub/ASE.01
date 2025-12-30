import hmac
import hashlib
import json
import base64
import time
import logging
from typing import Optional, Dict, Any, Tuple
from models import User, UserRole

logger = logging.getLogger(__name__)

# --- Configuration ---
# In a real app, this would be in st.secrets or env vars
JWT_SECRET = "ase_v3_super_secret_key_change_in_prod"
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRY_SECONDS = 3600  # 1 hour

class AuthManager:
    """
    Manages authentication, token generation, and permission checking using a simulated
    backend database and JWT-like token implementation.
    """

    def __init__(self):
        # Simulated Database of Users
        # In a real app, this connects to SQL/NoSQL
        self._users_db: Dict[str, dict] = {
            "admin@ase.test": {
                "id": "u-admin-001",
                "name": "Prof. Admin",
                "email": "admin@ase.test",
                "password_hash": self._hash_password("admin123"),
                "role": UserRole.ADMIN,
                "provider": "local"
            },
            "student@ase.test": {
                "id": "u-student-001",
                "name": "Student Tester",
                "email": "student@ase.test",
                "password_hash": self._hash_password("user123"),
                "role": UserRole.USER,
                "provider": "local"
            }
        }

    def _hash_password(self, password: str) -> str:
        """Simple SHA256 hash for simulation."""
        return hashlib.sha256(password.encode()).hexdigest()

    def login(self, email: str, password: str) -> Tuple[Optional[User], Optional[str]]:
        """
        Attempts to log in a user.
        Returns (User, token) if successful, else (None, None).
        """
        user_record = self._users_db.get(email)
        if not user_record:
            return None, None
        
        if user_record["password_hash"] == self._hash_password(password):
            # Password Match!
            user = User(
                id=user_record["id"],
                name=user_record["name"],
                email=user_record["email"],
                role=user_record["role"],
                provider=user_record["provider"]
            )
            token = self._generate_token(user)
            logger.info(f"User {email} logged in successfully as {user.role}")
            return user, token
        
        return None, None

    def _generate_token(self, user: User) -> str:
        """Generates a simulated JWT token."""
        payload = {
            "sub": user.id,
            "email": user.email,
            "role": user.role.value,
            "exp": int(time.time()) + TOKEN_EXPIRY_SECONDS
        }
        
        # Base64 Encode Payload
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        
        # Create Signature using HMAC
        signature = hmac.new(
            JWT_SECRET.encode(), 
            payload_b64.encode(), 
            hashlib.sha256
        ).hexdigest()
        
        return f"{payload_b64}.{signature}"

    def verify_token(self, token: str) -> Optional[User]:
        """
        Verifies a token and returns the User object if valid.
        Returns None if invalid or expired.
        """
        try:
            if not token or "." not in token:
                return None
                
            payload_b64, provided_signature = token.split(".")
            
            # Re-calculate signature
            expected_signature = hmac.new(
                JWT_SECRET.encode(), 
                payload_b64.encode(), 
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(provided_signature, expected_signature):
                logger.warning("Invalid token signature")
                return None
            
            # Decode Payload
            padded_payload = payload_b64 + "=" * (-len(payload_b64) % 4)
            payload_json = base64.urlsafe_b64decode(padded_payload).decode()
            payload = json.loads(payload_json)
            
            # Check Expiry
            if payload["exp"] < time.time():
                logger.warning("Token expired")
                return None
            
            # Reconstruct User (in a stateless system, we trust the token's role claim)
            # But for extra safety, we could look up the DB again to see if role changed.
            # Here we will trust the token for speed, mirroring a real stateless JWT flow.
            return User(
                id=payload["sub"],
                name=payload.get("name", "Unknown"), # Name might not be in minimal payload
                email=payload["email"],
                role=UserRole(payload["role"]),
                provider="jwt"
            )
            
        except Exception as e:
            logger.error(f"Token verification failed: {e}")
            return None

    def check_permission(self, user: User, required_role: UserRole) -> bool:
        """
        Checks if the user has the required permission level.
        Hierarchy: ADMIN > USER
        """
        if not user:
            return False
            
        if user.role == UserRole.ADMIN:
            return True # Admin can do everything
            
        if required_role == UserRole.USER:
            return True # User can do User things
            
        # If user is USER but required is ADMIN
        return False

    def process_oauth_login(self, provider: str, email: str, name: str) -> Tuple[Optional[User], Optional[str]]:
        """
        Simulates the backend processing of an OAuth callback.
        In a real app, this would exchange the code for a token, fetch the user profile,
        and then find/create the user in the DB.
        """
        # 1. Simulate finding/creating user
        user_record = self._users_db.get(email)
        
        if not user_record:
            # Create new user on the fly (JIT Provisioning)
            new_id = f"u-{provider}-{int(time.time())}"
            user_record = {
                "id": new_id,
                "name": name,
                "email": email,
                "password_hash": "OAUTH_EXTERNAL",
                "role": UserRole.USER, # Default role for new social signups
                "provider": provider
            }
            self._users_db[email] = user_record
            logger.info(f"New user provisioned via {provider}: {email}")
            
        # 2. Create User Object
        user = User(
            id=user_record["id"],
            name=user_record["name"],
            email=user_record["email"],
            role=user_record["role"],
            provider=user_record["provider"]
        )
        
        # 3. Issue Token
        token = self._generate_token(user)
        logger.info(f"OAuth login successful for {email} via {provider}")
        
        return user, token

# Pseudo-Singleton instance for easy import
auth_system = AuthManager()

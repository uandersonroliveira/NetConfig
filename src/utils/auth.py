"""Authentication utilities for JWT and password handling."""

import os
import stat
import secrets
import string
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from pathlib import Path

import bcrypt
import jwt

# JWT settings
JWT_SECRET_KEY_FILE = Path(__file__).parent.parent.parent / "data" / ".jwt_secret"
JWT_ALGORITHM = "HS256"
DEFAULT_TOKEN_EXPIRE_MINUTES = 480  # 8 hours


def _restrict_file_permissions(filepath: Path) -> None:
    """Restrict file permissions to owner only (cross-platform)."""
    try:
        if os.name == 'nt':
            # Windows: Use icacls to restrict permissions
            import subprocess
            # Remove inherited permissions and grant only current user full control
            subprocess.run(
                ['icacls', str(filepath), '/inheritance:r', '/grant:r', f'{os.getlogin()}:F'],
                capture_output=True,
                check=False
            )
        else:
            # Unix: Set permissions to 600 (owner read/write only)
            os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        # Log but don't fail if permission restriction fails
        pass


def _get_jwt_secret() -> str:
    """Get or create JWT secret key."""
    if JWT_SECRET_KEY_FILE.exists():
        return JWT_SECRET_KEY_FILE.read_text().strip()

    # Generate a secure random secret
    secret = secrets.token_urlsafe(64)
    JWT_SECRET_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    JWT_SECRET_KEY_FILE.write_text(secret)

    # Restrict file permissions to owner only
    _restrict_file_permissions(JWT_SECRET_KEY_FILE)

    return secret


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except Exception:
        return False


def create_access_token(
    user_id: str,
    username: str,
    role: str,
    expires_minutes: Optional[int] = None
) -> tuple[str, int]:
    """
    Create a JWT access token.

    Returns:
        Tuple of (token, expires_in_seconds)
    """
    if expires_minutes is None:
        expires_minutes = DEFAULT_TOKEN_EXPIRE_MINUTES

    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=expires_minutes)
    expires_in = expires_minutes * 60  # Convert to seconds

    payload = {
        "sub": user_id,
        "username": username,
        "role": str(role),  # Ensure enum is converted to string
        "exp": expire,
        "iat": now
    }

    secret = _get_jwt_secret()
    token = jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)

    return token, expires_in


def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Verify a JWT token and return its payload.

    Returns:
        Token payload dict or None if invalid/expired
    """
    try:
        secret = _get_jwt_secret()
        payload = jwt.decode(token, secret, algorithms=[JWT_ALGORITHM])
        return {
            "user_id": payload.get("sub"),
            "username": payload.get("username"),
            "role": payload.get("role"),
            "exp": payload.get("exp")
        }
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def generate_random_password(length: int = 16) -> str:
    """Generate a secure random password."""
    # Use a mix of uppercase, lowercase, digits, and special characters
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    # Ensure at least one of each type
    password = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*")
    ]
    # Fill the rest randomly
    password.extend(secrets.choice(alphabet) for _ in range(length - 4))
    # Shuffle to avoid predictable positions
    secrets.SystemRandom().shuffle(password)
    return ''.join(password)


def is_token_expiring_soon(token: str, threshold_minutes: int = 30) -> bool:
    """Check if token is expiring within the threshold."""
    payload = verify_token(token)
    if not payload:
        return True

    exp_timestamp = payload.get("exp")
    if not exp_timestamp:
        return True

    exp_datetime = datetime.fromtimestamp(exp_timestamp, tz=timezone.utc)
    threshold = datetime.now(timezone.utc) + timedelta(minutes=threshold_minutes)

    return exp_datetime <= threshold

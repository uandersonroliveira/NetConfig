"""Authentication API routes."""

from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, Header
from pydantic import BaseModel

from ..models.user import (
    User, UserResponse, LoginRequest, TokenResponse,
    AuthSettings, AuthSettingsUpdate, ADTestResult
)
from ..storage.json_storage import JsonStorage
from ..utils.auth import (
    hash_password, verify_password, create_access_token,
    verify_token, generate_random_password
)

router = APIRouter(tags=["Authentication"])
storage = JsonStorage()


# Dependency to get current user from token
async def get_current_user(authorization: Optional[str] = Header(None)) -> User:
    """Extract and validate JWT token, return current user."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Not authenticated")

    # Extract token from "Bearer <token>"
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    token = parts[1]
    payload = verify_token(token)

    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = storage.get_user(payload["user_id"])
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    if not user.is_active:
        raise HTTPException(status_code=401, detail="User account is disabled")

    return user


# Dependency for admin-only routes
async def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Require admin role for access."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


# Dependency for write access (blocks read-only users)
async def require_write_access(current_user: User = Depends(get_current_user)) -> User:
    """Block read-only users from write operations."""
    if current_user.role == "readonly":
        raise HTTPException(status_code=403, detail="Write access required")
    return current_user


# Optional auth - returns user if authenticated, None otherwise
async def get_optional_user(authorization: Optional[str] = Header(None)) -> Optional[User]:
    """Get current user if authenticated, None otherwise."""
    if not authorization:
        return None

    try:
        return await get_current_user(authorization)
    except HTTPException:
        return None


def user_to_response(user: User) -> UserResponse:
    """Convert User to UserResponse (excludes password_hash)."""
    return UserResponse(
        id=user.id,
        username=user.username,
        role=user.role,
        auth_type=user.auth_type,
        email=user.email,
        created_at=user.created_at,
        last_login=user.last_login,
        is_active=user.is_active,
        must_change_password=user.must_change_password
    )


def create_initial_admin() -> tuple[str, str]:
    """Create the initial admin user on first run. Returns (username, password)."""
    users = storage.list_users()
    if users:
        return None, None  # Users already exist

    # Generate a random password
    password = generate_random_password(16)

    # Create admin user
    admin = User(
        username="admin",
        password_hash=hash_password(password),
        role="admin",
        auth_type="local",
        is_active=True,
        must_change_password=True
    )

    storage.save_user(admin)
    return "admin", password


@router.post("/auth/login", response_model=TokenResponse)
async def login(credentials: LoginRequest):
    """Authenticate user and return JWT token."""
    # Check if AD authentication is requested
    if credentials.use_ad:
        auth_settings = storage.get_auth_settings()
        if not auth_settings.ad_enabled:
            raise HTTPException(status_code=400, detail="Active Directory authentication is not enabled")

        # Import LDAP client here to avoid circular imports
        try:
            from ..utils.ldap_client import LDAPClient
            ldap_client = LDAPClient(auth_settings.ad_settings)
            ad_result = ldap_client.authenticate(credentials.username, credentials.password)

            if not ad_result:
                raise HTTPException(status_code=401, detail="Invalid Active Directory credentials")

            # Check if user exists locally
            user = storage.get_user_by_username(credentials.username)

            if not user:
                # Create new AD user
                role = "readonly"  # Default role

                # Check AD groups for role mapping
                if auth_settings.ad_settings.admin_group:
                    user_groups = ldap_client.get_user_groups(credentials.username)
                    if auth_settings.ad_settings.admin_group in user_groups:
                        role = "admin"
                    elif auth_settings.ad_settings.readonly_group and auth_settings.ad_settings.readonly_group in user_groups:
                        role = "readonly"

                user = User(
                    username=credentials.username,
                    role=role,
                    auth_type="ad",
                    email=ad_result.get("email"),
                    is_active=True
                )
                storage.save_user(user)
            elif not user.is_active:
                raise HTTPException(status_code=401, detail="User account is disabled")

        except ImportError:
            raise HTTPException(status_code=500, detail="LDAP module not available")
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=401, detail=f"AD authentication failed: {str(e)}")
    else:
        # Local authentication
        user = storage.get_user_by_username(credentials.username)

        if not user:
            raise HTTPException(status_code=401, detail="Invalid username or password")

        if user.auth_type == "ad":
            raise HTTPException(status_code=400, detail="This user must authenticate via Active Directory")

        if not user.is_active:
            raise HTTPException(status_code=401, detail="User account is disabled")

        if not verify_password(credentials.password, user.password_hash):
            raise HTTPException(status_code=401, detail="Invalid username or password")

    # Update last login
    storage.update_user_last_login(user.id)

    # Get token expiration from settings
    auth_settings = storage.get_auth_settings()
    expires_minutes = auth_settings.session_timeout_minutes

    # Create token
    token, expires_in = create_access_token(
        user_id=user.id,
        username=user.username,
        role=user.role,
        expires_minutes=expires_minutes
    )

    return TokenResponse(
        token=token,
        token_type="bearer",
        expires_in=expires_in,
        user=user_to_response(user)
    )


@router.post("/auth/logout")
async def logout(current_user: User = Depends(get_current_user)):
    """Logout user (client-side token invalidation)."""
    # JWT tokens are stateless, so logout is handled client-side
    # by removing the token from storage
    return {"message": "Logged out successfully"}


@router.post("/auth/refresh", response_model=TokenResponse)
async def refresh_token(current_user: User = Depends(get_current_user)):
    """Refresh the access token."""
    auth_settings = storage.get_auth_settings()
    expires_minutes = auth_settings.session_timeout_minutes

    token, expires_in = create_access_token(
        user_id=current_user.id,
        username=current_user.username,
        role=current_user.role,
        expires_minutes=expires_minutes
    )

    return TokenResponse(
        token=token,
        token_type="bearer",
        expires_in=expires_in,
        user=user_to_response(current_user)
    )


@router.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    """Get current user information."""
    return user_to_response(current_user)


@router.get("/auth/settings")
async def get_auth_settings_endpoint(current_user: User = Depends(require_admin)):
    """Get authentication settings (admin only)."""
    settings = storage.get_auth_settings()
    # Don't expose the bind password
    settings_dict = settings.model_dump()
    if settings_dict.get("ad_settings", {}).get("bind_password"):
        settings_dict["ad_settings"]["bind_password"] = "********"
    return settings_dict


@router.put("/auth/settings")
async def update_auth_settings(
    updates: AuthSettingsUpdate,
    current_user: User = Depends(require_admin)
):
    """Update authentication settings (admin only)."""
    current_settings = storage.get_auth_settings()

    # Apply updates
    if updates.auth_enabled is not None:
        current_settings.auth_enabled = updates.auth_enabled
    if updates.session_timeout_minutes is not None:
        current_settings.session_timeout_minutes = updates.session_timeout_minutes
    if updates.ad_enabled is not None:
        current_settings.ad_enabled = updates.ad_enabled
    if updates.ad_settings is not None:
        # Only update non-empty fields
        ad = current_settings.ad_settings
        new_ad = updates.ad_settings
        if new_ad.server:
            ad.server = new_ad.server
        if new_ad.port:
            ad.port = new_ad.port
        ad.use_ssl = new_ad.use_ssl
        if new_ad.base_dn:
            ad.base_dn = new_ad.base_dn
        if new_ad.user_dn_pattern:
            ad.user_dn_pattern = new_ad.user_dn_pattern
        if new_ad.admin_group is not None:
            ad.admin_group = new_ad.admin_group
        if new_ad.readonly_group is not None:
            ad.readonly_group = new_ad.readonly_group
        if new_ad.bind_user is not None:
            ad.bind_user = new_ad.bind_user
        if new_ad.bind_password and new_ad.bind_password != "********":
            ad.bind_password = new_ad.bind_password
        current_settings.ad_settings = ad

    storage.save_auth_settings(current_settings)

    # Return updated settings (with password masked)
    settings_dict = current_settings.model_dump()
    if settings_dict.get("ad_settings", {}).get("bind_password"):
        settings_dict["ad_settings"]["bind_password"] = "********"

    return {"message": "Settings updated", "settings": settings_dict}


@router.post("/auth/ad/test", response_model=ADTestResult)
async def test_ad_connection(
    settings: AuthSettingsUpdate,
    current_user: User = Depends(require_admin)
):
    """Test Active Directory connection (admin only)."""
    try:
        from ..utils.ldap_client import LDAPClient

        # Get current settings and apply test settings
        current_settings = storage.get_auth_settings()
        test_settings = settings.ad_settings if settings.ad_settings else current_settings.ad_settings

        # If password is masked, use stored password
        if test_settings.bind_password == "********":
            test_settings.bind_password = storage.get_decrypted_ad_bind_password()

        ldap_client = LDAPClient(test_settings)
        success, message = ldap_client.test_connection()

        return ADTestResult(
            success=success,
            message=message
        )

    except ImportError:
        return ADTestResult(
            success=False,
            message="LDAP module not available. Install python-ldap package."
        )
    except Exception as e:
        return ADTestResult(
            success=False,
            message=f"Connection test failed: {str(e)}"
        )


@router.get("/auth/check")
async def check_auth_status():
    """Check if authentication is required (public endpoint)."""
    users = storage.list_users()
    auth_settings = storage.get_auth_settings()

    return {
        "auth_required": auth_settings.auth_enabled and len(users) > 0,
        "has_users": len(users) > 0,
        "ad_enabled": auth_settings.ad_enabled
    }

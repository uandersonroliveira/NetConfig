"""User and Authentication models for NetConfig."""

from datetime import datetime
from typing import Optional, Literal, List
from pydantic import BaseModel, Field
import uuid


class User(BaseModel):
    """User model for local and AD authentication."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    password_hash: Optional[str] = None  # None for AD users
    role: Literal["admin", "readonly"] = "readonly"
    auth_type: Literal["local", "ad"] = "local"
    email: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.now)
    last_login: Optional[datetime] = None
    is_active: bool = True
    must_change_password: bool = False


class UserCreate(BaseModel):
    """Model for creating a new user."""
    username: str
    password: str
    role: Literal["admin", "readonly"] = "readonly"
    email: Optional[str] = None


class UserUpdate(BaseModel):
    """Model for updating a user."""
    username: Optional[str] = None
    role: Optional[Literal["admin", "readonly"]] = None
    email: Optional[str] = None
    is_active: Optional[bool] = None


class UserResponse(BaseModel):
    """User response model (excludes password_hash)."""
    id: str
    username: str
    role: str
    auth_type: str
    email: Optional[str]
    created_at: datetime
    last_login: Optional[datetime]
    is_active: bool
    must_change_password: bool = False


class PasswordChange(BaseModel):
    """Model for changing password."""
    current_password: Optional[str] = None  # Required for self-change, optional for admin
    new_password: str


class LoginRequest(BaseModel):
    """Login request model."""
    username: str
    password: str
    use_ad: bool = False


class TokenResponse(BaseModel):
    """Token response after successful login."""
    token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
    user: UserResponse


class ADSettings(BaseModel):
    """Active Directory settings."""
    server: str = ""
    port: int = 389
    use_ssl: bool = False
    base_dn: str = ""
    user_dn_pattern: str = ""  # e.g., "{username}@domain.com" or "cn={username},ou=users,dc=example,dc=com"
    admin_group: Optional[str] = None  # AD group for admin role
    readonly_group: Optional[str] = None  # AD group for readonly role
    bind_user: Optional[str] = None
    bind_password: Optional[str] = None  # Will be encrypted when stored


class AuthSettings(BaseModel):
    """Authentication settings."""
    auth_enabled: bool = True
    session_timeout_minutes: int = 480  # 8 hours default
    ad_enabled: bool = False
    ad_settings: ADSettings = Field(default_factory=ADSettings)


class AuthSettingsUpdate(BaseModel):
    """Model for updating auth settings."""
    auth_enabled: Optional[bool] = None
    session_timeout_minutes: Optional[int] = None
    ad_enabled: Optional[bool] = None
    ad_settings: Optional[ADSettings] = None


class ADTestResult(BaseModel):
    """Result of AD connection test."""
    success: bool
    message: str
    details: Optional[dict] = None

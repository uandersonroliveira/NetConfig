"""User management API routes."""

from typing import List
from fastapi import APIRouter, HTTPException, Depends

from ..models.user import User, UserCreate, UserUpdate, UserResponse, PasswordChange
from ..storage.json_storage import JsonStorage
from ..utils.auth import hash_password, verify_password
from .auth import get_current_user, require_admin, user_to_response

router = APIRouter(prefix="/users", tags=["Users"])
storage = JsonStorage()


@router.get("", response_model=List[UserResponse])
async def list_users(current_user: User = Depends(require_admin)):
    """List all users (admin only)."""
    users = storage.list_users()
    return [user_to_response(u) for u in users]


@router.post("", response_model=UserResponse)
async def create_user(
    user_data: UserCreate,
    current_user: User = Depends(require_admin)
):
    """Create a new user (admin only)."""
    # Check if username already exists
    existing = storage.get_user_by_username(user_data.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    # Create new user
    new_user = User(
        username=user_data.username,
        password_hash=hash_password(user_data.password),
        role=user_data.role,
        email=user_data.email,
        auth_type="local",
        is_active=True,
        must_change_password=False
    )

    storage.save_user(new_user)
    return user_to_response(new_user)


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    current_user: User = Depends(require_admin)
):
    """Get a user by ID (admin only)."""
    user = storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user_to_response(user)


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    updates: UserUpdate,
    current_user: User = Depends(require_admin)
):
    """Update a user (admin only)."""
    user = storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check if trying to demote the last admin
    if updates.role == "readonly" and user.role == "admin":
        admin_count = storage.count_admin_users()
        if admin_count <= 1:
            raise HTTPException(
                status_code=400,
                detail="Cannot demote the last admin user"
            )

    # Check if trying to deactivate the last admin
    if updates.is_active is False and user.role == "admin" and user.is_active:
        admin_count = storage.count_admin_users()
        if admin_count <= 1:
            raise HTTPException(
                status_code=400,
                detail="Cannot deactivate the last admin user"
            )

    # Check if username is being changed and already exists
    if updates.username and updates.username != user.username:
        existing = storage.get_user_by_username(updates.username)
        if existing:
            raise HTTPException(status_code=400, detail="Username already exists")
        user.username = updates.username

    # Apply updates
    if updates.role is not None:
        user.role = updates.role
    if updates.email is not None:
        user.email = updates.email
    if updates.is_active is not None:
        user.is_active = updates.is_active

    storage.save_user(user)
    return user_to_response(user)


@router.delete("/{user_id}")
async def delete_user(
    user_id: str,
    current_user: User = Depends(require_admin)
):
    """Delete a user (admin only)."""
    user = storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Cannot delete self
    if user.id == current_user.id:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete your own account"
        )

    # Cannot delete the last admin
    if user.role == "admin":
        admin_count = storage.count_admin_users()
        if admin_count <= 1:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete the last admin user"
            )

    storage.delete_user(user_id)
    return {"message": "User deleted"}


@router.put("/{user_id}/password")
async def change_password(
    user_id: str,
    passwords: PasswordChange,
    current_user: User = Depends(get_current_user)
):
    """Change a user's password (self or admin)."""
    user = storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check if AD user
    if user.auth_type == "ad":
        raise HTTPException(
            status_code=400,
            detail="Cannot change password for Active Directory users"
        )

    # Non-admins can only change their own password
    if current_user.role != "admin" and current_user.id != user_id:
        raise HTTPException(
            status_code=403,
            detail="You can only change your own password"
        )

    # Non-admins must provide current password
    if current_user.role != "admin":
        if not passwords.current_password:
            raise HTTPException(
                status_code=400,
                detail="Current password is required"
            )
        if not verify_password(passwords.current_password, user.password_hash):
            raise HTTPException(
                status_code=400,
                detail="Current password is incorrect"
            )

    # Update password
    user.password_hash = hash_password(passwords.new_password)
    user.must_change_password = False
    storage.save_user(user)

    return {"message": "Password changed successfully"}


@router.put("/{user_id}/toggle-active")
async def toggle_user_active(
    user_id: str,
    current_user: User = Depends(require_admin)
):
    """Toggle user active status (admin only)."""
    user = storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Cannot deactivate self
    if user.id == current_user.id:
        raise HTTPException(
            status_code=400,
            detail="Cannot deactivate your own account"
        )

    # Cannot deactivate the last admin
    if user.role == "admin" and user.is_active:
        admin_count = storage.count_admin_users()
        if admin_count <= 1:
            raise HTTPException(
                status_code=400,
                detail="Cannot deactivate the last admin user"
            )

    user.is_active = not user.is_active
    storage.save_user(user)

    status = "activated" if user.is_active else "deactivated"
    return {"message": f"User {status}", "is_active": user.is_active}

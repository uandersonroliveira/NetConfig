"""Standardized API response models."""

from typing import Any, Generic, List, Optional, TypeVar
from pydantic import BaseModel

T = TypeVar('T')


class APIResponse(BaseModel, Generic[T]):
    """Standard API response wrapper."""
    success: bool = True
    message: Optional[str] = None
    data: Optional[T] = None


class ErrorResponse(BaseModel):
    """Standard error response."""
    success: bool = False
    message: str
    detail: Optional[str] = None
    code: Optional[str] = None


class PaginatedResponse(BaseModel, Generic[T]):
    """Paginated response for list endpoints."""
    success: bool = True
    data: List[T]
    total: int
    page: int = 1
    page_size: int = 50


class OperationResult(BaseModel):
    """Result of a bulk or background operation."""
    success: bool = True
    message: str
    total: int = 0
    succeeded: int = 0
    failed: int = 0
    details: Optional[List[dict]] = None


class BulkOperationResult(BaseModel):
    """Result of bulk add/delete operations."""
    success: bool = True
    message: str
    added: List[str] = []
    skipped: List[str] = []
    deleted: List[str] = []
    not_found: List[str] = []

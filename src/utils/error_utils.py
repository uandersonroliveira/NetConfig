"""Utilities for safe error handling and logging."""

import logging
import traceback
from typing import Optional

logger = logging.getLogger(__name__)


def safe_error_message(error: Exception, context: str = "", include_type: bool = True) -> str:
    """
    Create a safe error message that doesn't expose internal details.

    Logs the full error details server-side but returns a sanitized message.

    Args:
        error: The exception that occurred
        context: Additional context for logging (e.g., "AD authentication", "device connection")
        include_type: Whether to include the error type in the message

    Returns:
        A sanitized error message safe for end-user display
    """
    # Log full details server-side
    if context:
        logger.error(f"{context}: {type(error).__name__}: {error}")
    else:
        logger.error(f"{type(error).__name__}: {error}")
    logger.debug(traceback.format_exc())

    # List of sensitive patterns to filter out
    sensitive_patterns = [
        "password",
        "secret",
        "token",
        "key",
        "/home/",
        "/root/",
        "C:\\Users\\",
        "\\AppData\\",
        ".pem",
        ".key",
        "bind_dn",
        "credential",
    ]

    error_str = str(error).lower()
    for pattern in sensitive_patterns:
        if pattern.lower() in error_str:
            # Return generic message if sensitive info detected
            if include_type:
                return f"{type(error).__name__}: Operation failed"
            return "Operation failed"

    # For known safe error types, return the message
    safe_error_types = (
        ConnectionError,
        TimeoutError,
        ConnectionRefusedError,
        ConnectionResetError,
        OSError,
        ValueError,
        KeyError,
        AttributeError,
    )

    if isinstance(error, safe_error_types):
        # Truncate long messages
        msg = str(error)
        if len(msg) > 200:
            msg = msg[:197] + "..."

        if include_type:
            return f"{type(error).__name__}: {msg}"
        return msg

    # For unknown error types, return generic message
    if include_type:
        return f"{type(error).__name__}: An error occurred"
    return "An error occurred"


def get_connection_error_message(error: Exception, device_ip: str) -> str:
    """
    Get a user-friendly message for device connection errors.

    Args:
        error: The exception that occurred
        device_ip: IP address of the device

    Returns:
        A user-friendly error message
    """
    error_type = type(error).__name__
    error_str = str(error).lower()

    # Log full error
    logger.error(f"Connection error for {device_ip}: {error_type}: {error}")

    # Map common errors to friendly messages
    if "timeout" in error_str or isinstance(error, TimeoutError):
        return f"Connection to {device_ip} timed out"
    elif "refused" in error_str or isinstance(error, ConnectionRefusedError):
        return f"Connection to {device_ip} refused"
    elif "reset" in error_str or isinstance(error, ConnectionResetError):
        return f"Connection to {device_ip} was reset"
    elif "authentication" in error_str or "auth" in error_str:
        return f"Authentication failed for {device_ip}"
    elif "unreachable" in error_str or "no route" in error_str:
        return f"Device {device_ip} is unreachable"
    elif "permission" in error_str:
        return f"Permission denied for {device_ip}"
    else:
        return f"Failed to connect to {device_ip}"

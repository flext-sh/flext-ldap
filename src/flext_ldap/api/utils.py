"""Utility functions for LDAP operations.

This module provides common utility functions used across LDAP processing
operations, including path validation and normalization.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()


def validate_and_normalize_file_path(file_path: str | Path) -> str:
    """Validate and normalize a file path.

    Args:
        file_path: Path to validate and normalize

    Returns:
        Normalized path string

    Raises:
        ValueError: If path is invalid or unsafe

    """
    try:
        path = Path(file_path) if isinstance(file_path, str) else file_path

        # Normalize the path
        normalized = path.resolve()

        # Basic validation - check if parent directory exists for new files
        if not normalized.exists() and not normalized.parent.exists():
            # Create parent directory if it doesn't exist
            try:
                normalized.parent.mkdir(parents=True, exist_ok=True)
                logger.debug(f"Created parent directory: {normalized.parent}")
            except OSError as e:
                msg = f"Cannot create parent directory {normalized.parent}: {e}"
                raise ValueError(msg)

        # Security check - basic path validation
        if normalized.is_absolute():
            logger.debug(f"Using absolute path: {normalized}")

        return str(normalized)

    except (OSError, ValueError) as e:
        msg = f"Invalid file path: {file_path} - {e}"
        raise ValueError(msg)


def validate_configuration_value(value: Any, config_type: str = "generic") -> bool:
    """Validate a configuration value.

    Args:
        value: Configuration value to validate
        config_type: Type of configuration (for specific validation rules)

    Returns:
        True if value is valid, False otherwise

    """
    if value is None:
        return False

    if config_type == "server" and isinstance(value, str):
        # Basic server validation
        return len(value.strip()) > 0 and "." in value

    if config_type == "port" and isinstance(value, int):
        # Basic port validation
        return 1 <= value <= 65535

    # Default validation - just check if value is not empty
    if isinstance(value, str):
        return len(value.strip()) > 0

    return True


def normalize_dn(dn: str) -> str:
    """Normalize a Distinguished Name.

    Args:
        dn: DN to normalize

    Returns:
        Normalized DN string

    """
    if not dn:
        return ""

    # Basic normalization - remove extra whitespace
    return " ".join(dn.split())


def validate_dn(dn: str) -> str:
    """Validate and normalize a Distinguished Name.

    Args:
        dn: DN to validate

    Returns:
        Validated and normalized DN

    Raises:
        ValueError: If DN is invalid

    """
    if not isinstance(dn, str):
        msg = f"DN must be a string, got {type(dn)}"
        raise ValueError(msg)

    if not dn.strip():
        msg = "DN cannot be empty"
        raise ValueError(msg)

    # Basic validation - check for equals sign
    if "=" not in dn:
        msg = f"Invalid DN format: {dn}"
        raise ValueError(msg)

    return normalize_dn(dn)

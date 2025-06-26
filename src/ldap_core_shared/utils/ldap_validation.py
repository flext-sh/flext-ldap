"""LDAP Data Validation Utilities.

Generic LDAP validation functions for entries, attributes, and values.
"""

from __future__ import annotations

import re
import unicodedata
from pathlib import Path
from typing import Any, Dict

from ldap_core_shared.utils.dn_utils import normalize_dn, validate_dn_format


class PathValidationError(ValueError):
    """Raised when path validation fails."""


class ConfigValidationError(ValueError):
    """Raised when configuration validation fails."""


def validate_and_normalize_ldap_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and normalize a complete LDAP entry.
    
    Args:
        entry: LDAP entry dictionary
        
    Returns:
        Normalized and validated entry
        
    Raises:
        ValueError: If entry is invalid
    """
    if not isinstance(entry, dict):
        raise ValueError("Entry must be a dictionary")
    
    if "dn" not in entry:
        raise ValueError("Entry must have a 'dn' field")
    
    # Normalize DN
    entry["dn"] = normalize_dn(entry["dn"])
    
    # Validate and normalize attributes
    normalized_entry = {"dn": entry["dn"]}
    
    for attr_name, attr_value in entry.items():
        if attr_name == "dn":
            continue
            
        # Normalize attribute name
        normalized_attr_name = validate_and_normalize_attribute_name(attr_name)
        
        # Normalize attribute values
        if isinstance(attr_value, list):
            normalized_values = []
            for value in attr_value:
                normalized_values.append(validate_and_normalize_attribute_value(value))
            normalized_entry[normalized_attr_name] = normalized_values
        else:
            normalized_entry[normalized_attr_name] = validate_and_normalize_attribute_value(attr_value)
    
    return normalized_entry


def validate_and_normalize_attribute_name(attr_name: str) -> str:
    """Validate and normalize LDAP attribute name.
    
    Args:
        attr_name: Attribute name to validate
        
    Returns:
        Normalized attribute name
        
    Raises:
        ValueError: If attribute name is invalid
    """
    if not isinstance(attr_name, str):
        raise ValueError("Attribute name must be a string")
    
    # Remove dangerous whitespace
    attr_name = attr_name.strip()
    
    if not attr_name:
        raise ValueError("Attribute name cannot be empty")
    
    # Normalize Unicode
    attr_name = unicodedata.normalize("NFC", attr_name)
    
    # Validate attribute name format (LDAP standard)
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9\-;]*$", attr_name):
        raise ValueError(f"Invalid attribute name format: {attr_name}")
    
    return attr_name.lower()


def validate_and_normalize_attribute_value(attr_value: Any) -> str:
    """Validate and normalize LDAP attribute value.
    
    Args:
        attr_value: Attribute value to validate
        
    Returns:
        Normalized attribute value as string
        
    Raises:
        ValueError: If attribute value is invalid
    """
    if attr_value is None:
        return ""
    
    # Convert to string
    if not isinstance(attr_value, str):
        attr_value = str(attr_value)
    
    # Remove dangerous leading/trailing whitespace
    attr_value = attr_value.strip()
    
    # Normalize Unicode
    try:
        attr_value = unicodedata.normalize("NFC", attr_value)
    except Exception as e:
        raise ValueError(f"Unicode normalization failed: {e}") from e
    
    # Basic security check - no null bytes
    if "\x00" in attr_value:
        raise ValueError("Attribute value cannot contain null bytes")
    
    return attr_value


def validate_dn(dn: str) -> str:
    """Validate DN using ldap-core-shared validation.
    
    Args:
        dn: DN string to validate
        
    Returns:
        Normalized DN string
        
    Raises:
        ValueError: If DN is invalid
    """
    is_valid, error_message = validate_dn_format(dn)
    if not is_valid:
        raise ValueError(f"Invalid DN: {error_message}")
    
    return normalize_dn(dn)


def validate_and_normalize_file_path(file_path: Path, base_path: Path) -> Path:
    """Validate and normalize file path preventing path traversal attacks.
    
    Args:
        file_path: Input file path
        base_path: Allowed base directory
        
    Returns:
        Validated absolute path
        
    Raises:
        PathValidationError: If path is invalid or outside base
    """
    if not isinstance(file_path, Path):
        try:
            file_path = Path(file_path)
        except Exception as e:
            raise PathValidationError(f"Invalid path format: {e}") from e
    
    if not isinstance(base_path, Path):
        try:
            base_path = Path(base_path)
        except Exception as e:
            raise PathValidationError(f"Invalid base path format: {e}") from e
    
    try:
        # Resolve to absolute paths to handle .. and . components
        resolved_file = file_path.resolve()
        resolved_base = base_path.resolve()
        
        # Check if file path is within base path
        try:
            resolved_file.relative_to(resolved_base)
        except ValueError as e:
            raise PathValidationError(
                f"Path traversal attempt detected: {file_path} is outside {base_path}"
            ) from e
        
        return resolved_file
    
    except Exception as e:
        raise PathValidationError(f"Path resolution failed: {e}") from e


def validate_configuration_value(
    config_key: str, 
    config_value: Any, 
    allowed_types: tuple = (str, int, float, bool, list, dict)
) -> Any:
    """Validate configuration value for security and type safety.
    
    Args:
        config_key: Configuration key name
        config_value: Configuration value to validate
        allowed_types: Tuple of allowed types
        
    Returns:
        Validated configuration value
        
    Raises:
        ConfigValidationError: If configuration value is invalid
    """
    if config_value is None:
        raise ConfigValidationError(f"Configuration value for '{config_key}' cannot be None")
    
    if not isinstance(config_value, allowed_types):
        raise ConfigValidationError(
            f"Configuration value for '{config_key}' must be one of {allowed_types}, "
            f"got {type(config_value)}"
        )
    
    # Security check for string values
    if isinstance(config_value, str):
        if "\x00" in config_value:
            raise ConfigValidationError(
                f"Configuration value for '{config_key}' cannot contain null bytes"
            )
        
        # Normalize Unicode
        try:
            config_value = unicodedata.normalize("NFC", config_value)
        except Exception as e:
            raise ConfigValidationError(
                f"Unicode normalization failed for '{config_key}': {e}"
            ) from e
    
    return config_value
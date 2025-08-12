"""LDAP utilities following DRY principle.

This module provides comprehensive LDAP utility functions for the FLEXT
ecosystem, including DN manipulation, filter building, time parsing,
URL handling, and attribute validation. All functions follow enterprise
security patterns and RFC compliance.

Key Features:
    - DN (Distinguished Name) parsing and manipulation
    - LDAP filter building with automatic escaping
    - GeneralizedTime format parsing and formatting
    - LDAP URL parsing and component extraction
    - Attribute name and value validation
    - Security-focused filter character escaping

Security Notes:
    All functions that handle user input implement proper escaping
    and validation to prevent LDAP injection attacks and ensure
    RFC compliance.

Example:
    Basic LDAP utilities usage:

    >>> from flext_ldap.utils import flext_ldap_build_filter, flext_ldap_parse_dn
    >>>
    >>> # Build secure LDAP filter
    >>> conditions = {"cn": "admin", "objectClass": "person"}
    >>> filter_str = flext_ldap_build_filter("and", conditions)
    >>> print(filter_str)
    (&(cn=admin)(objectClass=person))
    >>>
    >>> # Parse DN components
    >>> dn = "cn=admin,ou=users,dc=example,dc=com"
    >>> components = flext_ldap_parse_dn(dn)
    >>> print(components[0])
    {'attribute': 'cn', 'value': 'admin'}

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol
from urllib.parse import parse_qs, urlparse

from flext_core import get_logger

if TYPE_CHECKING:
    from collections.abc import Callable

    from flext_core import FlextTypes

logger = get_logger(__name__)


def flext_ldap_escape_filter_chars(value: str) -> str:
    r"""Escape special characters in LDAP filter values.

    Properly escapes LDAP special characters to prevent filter injection
    attacks and ensure correct filter interpretation. Follows RFC 4515
    specifications for LDAP search filter escaping.

    Args:
        value: The string value to escape for use in LDAP filters.

    Returns:
        The escaped string safe for use in LDAP filter expressions.

    Example:
        >>> flext_ldap_escape_filter_chars("user*(admin)")
        'user\\2a(admin\\29'
        >>> flext_ldap_escape_filter_chars("normal_value")
        'normal_value'

    Note:
        Escapes these special characters:
        - \\ (backslash) → \\5c
        - * (asterisk) → \\2a
        - ( (left parenthesis) → \\28
        - ) (right parenthesis) → \\29
        - \x00 (null byte) → \\00

    """
    logger.trace(
        "Escaping LDAP filter characters",
        extra={"original_value": value, "original_length": len(value)},
    )

    # Escape backslash first to avoid double escaping
    result = value.replace("\\", r"\5c")

    # Then escape other characters
    escape_map = {
        "*": r"\2a",
        "(": r"\28",
        ")": r"\29",
        "\x00": r"\00",
    }

    for char, replacement in escape_map.items():
        result = result.replace(char, replacement)

    logger.debug(
        "LDAP filter characters escaped",
        extra={"original": value, "escaped": result, "was_changed": value != result},
    )
    return result


def flext_ldap_escape_filter_value(value: str) -> str:
    """Escape filter value - alias for flext_ldap_escape_filter_chars."""
    return flext_ldap_escape_filter_chars(value)


def flext_ldap_parse_generalized_time(time_str: str) -> datetime:
    """Parse LDAP generalized time format into datetime object.

    Parses LDAP GeneralizedTime format (YYYYMMDDHHMMSZ) into a
    timezone-aware datetime object. Handles both timezone-aware
    and timezone-naive input strings.

    Args:
        time_str: LDAP generalized time string in YYYYMMDDHHMMSS[Z] format.
                 Z suffix indicates UTC timezone.

    Returns:
        Timezone-aware datetime object. Always returns UTC timezone
        for consistency, even if input has no timezone suffix.

    Raises:
        ValueError: If time_str cannot be parsed as valid datetime format.

    Example:
        >>> dt = flext_ldap_parse_generalized_time("20240301120000Z")
        >>> print(dt.isoformat())
        '2024-03-01T12:00:00+00:00'
        >>> dt2 = flext_ldap_parse_generalized_time("20240301120000")
        >>> print(dt2.tzinfo)
        datetime.timezone.utc

    Note:
        - Input format: YYYYMMDDHHMMSS[Z]
        - Output is always timezone-aware (UTC)
        - Z suffix is optional but recommended

    """
    logger.trace(
        "Parsing LDAP generalized time",
        extra={"time_string": time_str, "has_z_suffix": time_str.endswith("Z")},
    )

    # Remove Z suffix if present
    tz = None
    if time_str.endswith("Z"):
        time_str = time_str[:-1]
        tz = UTC
        logger.trace("Removed Z suffix, will use UTC timezone")

    # Parse the time string
    # Always create timezone-aware datetime for consistency
    dt = datetime.strptime(time_str, "%Y%m%d%H%M%S").replace(tzinfo=UTC)

    logger.debug(
        "LDAP generalized time parsed",
        extra={
            "original": time_str + ("Z" if tz else ""),
            "parsed": dt.isoformat(),
            "has_timezone": dt.tzinfo is not None,
        },
    )
    return dt


def flext_ldap_format_generalized_time(dt: datetime) -> str:
    """Format datetime to LDAP generalized time format."""
    logger.trace(
        "Formatting datetime to LDAP generalized time",
        extra={"datetime": dt.isoformat(), "has_timezone": dt.tzinfo is not None},
    )

    time_str = dt.strftime("%Y%m%d%H%M%S")
    if dt.tzinfo is not None:
        time_str += "Z"
        logger.trace("Added Z suffix for timezone-aware datetime")

    logger.debug(
        "Datetime formatted to LDAP generalized time",
        extra={"original": dt.isoformat(), "formatted": time_str},
    )
    return time_str


def flext_ldap_validate_dn(dn: str) -> bool:
    """Validate distinguished name (DN) format according to RFC standards.

    Performs basic validation of DN format by checking that each component
    contains an equals sign separating attribute name from value.

    Args:
        dn: Distinguished name string to validate.

    Returns:
        True if DN format appears valid, False otherwise.

    Example:
        >>> flext_ldap_validate_dn("cn=admin,dc=example,dc=com")
        True
        >>> flext_ldap_validate_dn("invalid-dn-format")
        False
        >>> flext_ldap_validate_dn("")
        False

    Note:
        This is basic format validation only. It does not verify:
        - Actual attribute name validity
        - Value format correctness
        - LDAP server schema compliance

    """
    if not dn:
        return False

    parts = dn.split(",")
    return all("=" in part.strip() for part in parts)


def flext_ldap_normalize_dn(dn: str) -> str:
    """Normalize distinguished name for comparison."""
    parts = []
    for raw_part in dn.split(","):
        part = raw_part.strip()
        if "=" in part:
            attr, value = part.split("=", 1)
            parts.append(f"{attr.strip().lower()}={value.strip().lower()}")

    return ",".join(parts)


def flext_ldap_split_dn(dn: str) -> list[str]:
    """Split distinguished name into components."""
    if not dn:
        return []

    return [part.strip() for part in dn.split(",") if part.strip()]


def flext_ldap_compare_dns(dn1: str, dn2: str) -> bool:
    """Compare two distinguished names after normalization."""
    return flext_ldap_normalize_dn(dn1) == flext_ldap_normalize_dn(dn2)


def flext_ldap_build_filter(operator: str, conditions: dict[str, str]) -> str:
    r"""Build LDAP filter from conditions using Railway-Oriented Programming.

    Constructs proper LDAP search filters from attribute-value pairs
    using the specified logical operator. Automatically escapes
    special characters in values to prevent filter injection.

    Args:
        operator: Logical operator for combining conditions.
                 Supported values: 'and', 'or', 'not'
        conditions: Dictionary mapping attribute names to values.
                   Each key-value pair becomes a filter condition.

    Returns:
        Complete LDAP filter string ready for use in search operations.
        Returns empty string if no conditions provided or invalid operator.

    Example:
        >>> conditions = {"cn": "admin", "objectClass": "person"}
        >>> flext_ldap_build_filter("and", conditions)
        '(&(cn=admin)(objectClass=person))'
        >>>
        >>> flext_ldap_build_filter("or", {"uid": "user*"})
        '(|(uid=user\\2a))'
        >>>
        >>> flext_ldap_build_filter("not", {"disabled": "true"})
        '(!(disabled=true))'

    Note:
        - Values are automatically escaped for LDAP filter safety
        - Single conditions are optimized for proper filter syntax
        - Empty conditions return empty string
        - Invalid operators return empty string

    """
    # Early return for empty conditions
    if not conditions:
        return ""

    # Build individual filter components
    filters = [
        f"({attr}={flext_ldap_escape_filter_chars(value)})"
        for attr, value in conditions.items()
    ]

    # Filter assembly pipeline - consolidated mapping approach
    filter_builders: dict[tuple[str, bool], Callable[[list[str]], str]] = {
        ("not", True): lambda f: f"(!{f[0]})",  # Single filter negation
        ("not", False): lambda f: f"(!(&{''.join(f)}))",  # Multiple filter negation
        ("and", True): lambda f: f"(&{f[0]})",  # Single AND operation
        ("and", False): lambda f: f"(&{''.join(f)})",  # AND operation
        ("or", True): lambda f: f"(|{f[0]})",  # Single OR operation
        ("or", False): lambda f: f"(|{''.join(f)})",  # OR operation
    }

    # Determine filter key based on operator and single filter condition
    is_single_filter = len(filters) == 1
    filter_key = (operator, is_single_filter)

    # Execute appropriate filter builder or return empty string
    builder = filter_builders.get(filter_key)
    return str(builder(filters)) if builder else ""


def flext_ldap_is_valid_url(url: str) -> bool:
    """Check if URL is a valid LDAP URL."""
    try:
        parsed = urlparse(url)
    except (ValueError, TypeError):
        return False
    else:
        return parsed.scheme in {"ldap", "ldaps"}


# Constants for LDAP URL parsing
LDAP_URL_ATTRIBUTES_INDEX = 1
LDAP_URL_SCOPE_INDEX = 2
LDAP_URL_FILTER_INDEX = 3


def flext_ldap_parse_url(url: str) -> FlextTypes.Core.JsonDict:
    """Parse LDAP URL into structured components.

    Parses LDAP URLs according to RFC 4516 format and extracts
    all components including connection details and search parameters.

    Args:
        url: LDAP URL string in standard format:
             ldap[s]://host[:port]/base_dn[?attrs[?scope[?filter]]]

    Returns:
        Dictionary containing parsed URL components:
        - scheme: 'ldap' or 'ldaps'
        - host: hostname or IP address (default: 'localhost')
        - port: port number (default: 389 for ldap, 636 for ldaps)
        - base_dn: base distinguished name for searches
        - attributes: list of attribute names to retrieve
        - scope: search scope ('base', 'one', 'sub')
        - filter: LDAP search filter expression

    Example:
        >>> url = "ldap://server:389/dc=example,dc=com?cn,mail?sub?(objectClass=person)"
        >>> parsed = flext_ldap_parse_url(url)
        >>> print(parsed['host'])
        'server'
        >>> print(parsed['attributes'])
        ['cn', 'mail']
        >>> print(parsed['filter'])
        '(objectClass=person)'

    Note:
        - Missing components get sensible defaults
        - Supports both ldap:// and ldaps:// schemes
        - Base DN path component has leading slash stripped

    """
    parsed = urlparse(url)

    # Parse query string
    parse_qs(parsed.query) if parsed.query else {}

    # Extract components
    result = {
        "scheme": parsed.scheme,
        "host": parsed.hostname or "localhost",
        "port": parsed.port or (389 if parsed.scheme == "ldap" else 636),
        "base_dn": parsed.path.lstrip("/") if parsed.path else "",
        "attributes": [],
        "scope": "sub",
        "filter": "(objectClass=*)",
    }

    # Parse LDAP URL format: ldap://host:port/base_dn?attrs?scope?filter
    if parsed.path and "?" in url:
        parts = url.split("?")
        if len(parts) > LDAP_URL_ATTRIBUTES_INDEX and parts[LDAP_URL_ATTRIBUTES_INDEX]:
            result["attributes"] = (
                parts[LDAP_URL_ATTRIBUTES_INDEX].split(",")
                if parts[LDAP_URL_ATTRIBUTES_INDEX]
                else []
            )
        if len(parts) > LDAP_URL_SCOPE_INDEX and parts[LDAP_URL_SCOPE_INDEX]:
            result["scope"] = parts[LDAP_URL_SCOPE_INDEX]
        if len(parts) > LDAP_URL_FILTER_INDEX and parts[LDAP_URL_FILTER_INDEX]:
            result["filter"] = parts[LDAP_URL_FILTER_INDEX]

    return result


def flext_ldap_parse_dn(dn: str) -> list[dict[str, str]]:
    """Parse distinguished name into components."""
    components = []
    parts = dn.split(",")

    for raw_part in parts:
        part = raw_part.strip()
        if "=" in part:
            attr, value = part.split("=", 1)
            components.append({"attribute": attr.strip(), "value": value.strip()})

    return components


def flext_ldap_build_dn(components: list[dict[str, str]]) -> str:
    """Build distinguished name from components."""
    parts = []
    for component in components:
        attr = component["attribute"]
        value = component["value"]
        parts.append(f"{attr}={value}")

    return ",".join(parts)


def flext_ldap_normalize_attribute_name(name: str) -> str:
    """Normalize attribute name."""
    return name.lower().strip()


def flext_ldap_validate_attribute_name(name: str) -> bool:
    """Validate LDAP attribute name according to RFC 4512."""
    if not name:
        return False

    # LDAP attribute names: letters, digits, hyphens
    # Must start with letter
    pattern = r"^[a-zA-Z][a-zA-Z0-9\-]*$"
    return bool(re.match(pattern, name))


def flext_ldap_validate_attribute_value(value: object, max_length: int = 1000) -> bool:
    """Validate LDAP attribute value according to LDAP standards."""
    if value is None:
        return True

    # Convert to string for validation
    str_value = str(value)

    # Basic length check (LDAP typically has limits)
    return len(str_value) <= max_length


def flext_ldap_sanitize_attribute_name(name: str) -> str:
    """Sanitize field name to be LDAP-compatible."""
    # Use flext-ldap normalization as base
    normalized = flext_ldap_normalize_attribute_name(name)

    # Remove invalid characters
    sanitized = re.sub(r"[^a-zA-Z0-9\-]", "", normalized)

    # Ensure starts with letter
    if sanitized and not sanitized[0].isalpha():
        sanitized = "attr" + sanitized

    # Fallback if empty
    if not sanitized:
        sanitized = "unknownAttr"

    return sanitized


class FlextLdapTimestampProtocol(Protocol):
    """Protocol for objects with strftime method."""

    def strftime(self, fmt: str) -> str:
        """Format timestamp as string."""
        ...


def flext_ldap_format_timestamp(
    timestamp: datetime | FlextLdapTimestampProtocol | str,
) -> str:
    """Format timestamp for LDAP."""
    if isinstance(timestamp, str):
        return timestamp
    return timestamp.strftime("%Y%m%d%H%M%SZ")


# Backward compatibility alias
TimestampProtocol = FlextLdapTimestampProtocol

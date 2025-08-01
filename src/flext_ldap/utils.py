# Copyright (c) 2025 FLEXT
# SPDX-License-Identifier: MIT

"""LDAP utilities following DRY principle."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import parse_qs, urlparse

from flext_core import get_logger

logger = get_logger(__name__)


def flext_ldap_escape_filter_chars(value: str) -> str:
    """Escape special characters in LDAP filter values."""
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
    """Parse LDAP generalized time format."""
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
    # Create timezone-aware datetime directly
    dt = datetime.strptime(time_str, "%Y%m%d%H%M%S").replace(tzinfo=UTC if tz else None)

    # If no timezone was specified, make it timezone-naive
    if not tz and dt.tzinfo:
        dt = dt.replace(tzinfo=None)

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
    """Validate distinguished name format."""
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
    """Build LDAP filter from conditions using Railway-Oriented Programming."""
    # Early return for empty conditions
    if not conditions:
        return ""

    # Build individual filter components
    filters = [
        f"({attr}={flext_ldap_escape_filter_chars(value)})"
        for attr, value in conditions.items()
    ]

    # Filter assembly pipeline - consolidated mapping approach
    filter_builders = {
        ("not", True): lambda f: f"(!{f[0]})",  # Single filter negation
        ("not", False): lambda f: f"(!(&{''.join(f)}))",  # Multiple filter negation
        ("and", False): lambda f: f"(&{''.join(f)})",  # AND operation
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


def flext_ldap_parse_url(url: str) -> dict[str, object]:
    """Parse LDAP URL into components."""
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

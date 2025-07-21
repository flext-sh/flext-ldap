# Copyright (c) 2025 FLEXT
# SPDX-License-Identifier: MIT

"""LDAP utilities following DRY principle."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import parse_qs, urlparse


def escape_filter_chars(value: str) -> str:
    """Escape special characters in LDAP filter values."""
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

    return result


def escape_filter_value(value: str) -> str:
    """Escape filter value - alias for escape_filter_chars."""
    return escape_filter_chars(value)


def parse_generalized_time(time_str: str) -> datetime:
    """Parse LDAP generalized time format."""
    # Remove Z suffix if present
    tz = None
    if time_str.endswith("Z"):
        time_str = time_str[:-1]
        tz = UTC

    # Parse the time string
    dt = datetime.strptime(time_str, "%Y%m%d%H%M%S")  # noqa: DTZ007

    if tz:
        dt = dt.replace(tzinfo=tz)

    return dt


def format_generalized_time(dt: datetime) -> str:
    """Format datetime to LDAP generalized time format."""
    time_str = dt.strftime("%Y%m%d%H%M%S")
    if dt.tzinfo is not None:
        time_str += "Z"
    return time_str


def validate_dn(dn: str) -> bool:
    """Validate distinguished name format."""
    if not dn:
        return False

    parts = dn.split(",")
    return all("=" in part.strip() for part in parts)


def normalize_dn(dn: str) -> str:
    """Normalize distinguished name for comparison."""
    parts = []
    for raw_part in dn.split(","):
        part = raw_part.strip()
        if "=" in part:
            attr, value = part.split("=", 1)
            parts.append(f"{attr.strip().lower()}={value.strip().lower()}")

    return ",".join(parts)


def split_dn(dn: str) -> list[str]:
    """Split distinguished name into components."""
    if not dn:
        return []

    return [part.strip() for part in dn.split(",") if part.strip()]


def compare_dns(dn1: str, dn2: str) -> bool:
    """Compare two distinguished names after normalization."""
    return normalize_dn(dn1) == normalize_dn(dn2)


def build_filter(operator: str, conditions: dict[str, str]) -> str:
    """Build LDAP filter from conditions."""
    if not conditions:
        return ""

    filters = []
    for attr, value in conditions.items():
        escaped_value = escape_filter_chars(value)
        filters.append(f"({attr}={escaped_value})")

    if len(filters) == 1 and operator == "not":
        return f"(!{filters[0]})"
    if operator == "and":
        return f"(&{''.join(filters)})"
    if operator == "or":
        return f"(|{''.join(filters)})"
    if operator == "not":
        return f"(!(&{''.join(filters)}))"
    return ""


def is_valid_ldap_url(url: str) -> bool:
    """Check if URL is a valid LDAP URL."""
    try:
        parsed = urlparse(url)
    except (ValueError, TypeError):
        return False
    else:
        return parsed.scheme in {"ldap", "ldaps"}


def parse_ldap_url(url: str) -> dict[str, Any]:
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
        if len(parts) > 1 and parts[1]:
            result["attributes"] = parts[1].split(",") if parts[1] else []
        if len(parts) > 2 and parts[2]:
            result["scope"] = parts[2]
        if len(parts) > 3 and parts[3]:
            result["filter"] = parts[3]

    return result


def parse_dn(dn: str) -> list[dict[str, str]]:
    """Parse distinguished name into components."""
    components = []
    parts = dn.split(",")

    for raw_part in parts:
        part = raw_part.strip()
        if "=" in part:
            attr, value = part.split("=", 1)
            components.append({"attribute": attr.strip(), "value": value.strip()})

    return components


def build_dn(components: list[dict[str, str]]) -> str:
    """Build distinguished name from components."""
    parts = []
    for component in components:
        attr = component["attribute"]
        value = component["value"]
        parts.append(f"{attr}={value}")

    return ",".join(parts)


def normalize_attribute_name(name: str) -> str:
    """Normalize attribute name."""
    return name.lower().strip()


class TimestampProtocol(Protocol):
    """Protocol for objects with strftime method."""

    def strftime(self, fmt: str) -> str:
        """Format timestamp as string."""
        ...


def format_ldap_timestamp(timestamp: datetime | TimestampProtocol | str) -> str:
    """Format timestamp for LDAP."""
    if isinstance(timestamp, str):
        return timestamp
    return timestamp.strftime("%Y%m%d%H%M%SZ")

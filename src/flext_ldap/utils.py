# Copyright (c) 2025 FLEXT
# SPDX-License-Identifier: MIT

"""LDAP utilities following DRY principle."""

from __future__ import annotations


def escape_filter_value(value: str) -> str:
    """Escape special characters in LDAP filter values.

    Returns:
        str: The escaped value safe for LDAP filters.

    """
    escape_map = {
        "(": "\\28",
        ")": "\\29",
        "\\": "\\5c",
        "*": "\\2a",
        "/": "\\2f",
        "\x00": "\\00",
    }

    result = value
    for char, replacement in escape_map.items():
        result = result.replace(char, replacement)

    return result


def parse_dn(dn: str) -> list[dict[str, str]]:
    """Parse distinguished name into components.

    Returns:
        list[dict[str, str]]: List of DN components with attribute and value keys.

    """
    components = []
    parts = dn.split(",")

    for raw_part in parts:
        part = raw_part.strip()
        if "=" in part:
            attr, value = part.split("=", 1)
            components.append({"attribute": attr.strip(), "value": value.strip()})

    return components


def build_dn(components: list[dict[str, str]]) -> str:
    """Build distinguished name from components.

    Returns:
        str: The constructed DN string.

    """
    parts = []
    for component in components:
        attr = component["attribute"]
        value = component["value"]
        parts.append(f"{attr}={value}")

    return ",".join(parts)


def normalize_attribute_name(name: str) -> str:
    """Normalize LDAP attribute name.

    Returns:
        str: The normalized attribute name in lowercase.

    """
    return name.lower().strip()


def format_ldap_timestamp(timestamp: object) -> str:
    """Format timestamp for LDAP.

    Returns:
        str: The formatted timestamp in LDAP format (YYYYMMDDHHmmssZ).

    """
    if hasattr(timestamp, "strftime"):
        return str(timestamp.strftime("%Y%m%d%H%M%SZ"))
    return str(timestamp)

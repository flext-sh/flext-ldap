"""Simplified Data Type Converter - Uses ldap3's native capabilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Refactored to eliminate duplication with ldap3's built-in type handling.
Focuses only on FLEXT-specific business logic.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from flext_core import FlextResult, get_logger

logger = get_logger(__name__)


class FlextLdapDataType(Enum):
    """Simplified LDAP data types focusing on business logic."""

    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    BINARY = "binary"
    DATE_TIME = "datetime"
    DN = "dn"
    EMAIL = "email"
    PHONE = "phone"
    URL = "url"
    IP_ADDRESS = "ip_address"
    MAC_ADDRESS = "mac_address"
    UUID = "uuid"
    CERTIFICATE = "certificate"
    PASSWORD = "password"
    UNKNOWN = "unknown"


class FlextSimpleConverter:
    """Simplified converter that leverages ldap3's native type handling.

    Only provides business-specific conversions not available in ldap3.
    """

    def __init__(self) -> None:
        """Initialize the simplified converter."""

    async def detect_type(self, value: Any) -> FlextResult[FlextLdapDataType]:
        """Detect LDAP data type from value (test compatibility)."""
        try:
            if value is None:
                return FlextResult.ok(FlextLdapDataType.UNKNOWN)

            if not isinstance(value, str):
                value = str(value)

            detected_type = self.detect_business_type(value)
            return FlextResult.ok(detected_type)

        except Exception as e:
            return FlextResult.fail(f"Failed to detect data type: {e}")

    def detect_business_type(self, value: str) -> FlextLdapDataType:
        """Detect business-specific data types."""
        if not value:
            return FlextLdapDataType.STRING

        # Only detect types that require business logic
        if self._is_email(value):
            return FlextLdapDataType.EMAIL
        if self._is_dn(value):
            return FlextLdapDataType.DN
        if self._is_datetime(value):
            return FlextLdapDataType.DATE_TIME
        if self._is_boolean_text(value):
            return FlextLdapDataType.BOOLEAN
        if value.isdigit():
            return FlextLdapDataType.INTEGER
        return FlextLdapDataType.STRING

    def normalize_email(self, email: str) -> FlextResult[str]:
        """Normalize email address for LDAP storage."""
        try:
            normalized = email.lower().strip()
            if self._is_email(normalized):
                return FlextResult.ok(normalized)
            return FlextResult.fail(f"Invalid email format: {email}")
        except Exception as e:
            return FlextResult.fail(f"Email normalization failed: {e}")

    def normalize_dn(self, dn: str) -> FlextResult[str]:
        """Normalize distinguished name."""
        try:
            # Basic DN normalization - ldap3 handles the complex parsing
            normalized = dn.strip()
            if self._is_dn(normalized):
                return FlextResult.ok(normalized)
            return FlextResult.fail(f"Invalid DN format: {dn}")
        except Exception as e:
            return FlextResult.fail(f"DN normalization failed: {e}")

    def convert_to_ldap_time(self, dt: datetime) -> str:
        """Convert datetime to LDAP GeneralizedTime format."""
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.strftime("%Y%m%d%H%M%SZ")

    def parse_ldap_time(self, ldap_time: str) -> FlextResult[datetime]:
        """Parse LDAP GeneralizedTime to datetime."""
        try:
            # Handle common LDAP time formats
            if ldap_time.endswith("Z"):
                if len(ldap_time) == 15:  # YYYYMMDDHHMMSSZ
                    dt = datetime.strptime(ldap_time, "%Y%m%d%H%M%SZ")
                elif len(ldap_time) == 13:  # YYMMDDHHMMSSZ
                    dt = datetime.strptime(ldap_time, "%y%m%d%H%M%SZ")
                else:
                    return FlextResult.fail(
                        f"Unsupported LDAP time format: {ldap_time}",
                    )

                return FlextResult.ok(dt.replace(tzinfo=UTC))
            return FlextResult.fail(f"Invalid LDAP time format: {ldap_time}")
        except ValueError as e:
            return FlextResult.fail(f"Failed to parse LDAP time: {e}")

    # Simple detection methods for business types
    def _is_email(self, value: str) -> bool:
        """Check if value looks like an email."""
        return bool(
            re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value),
        )

    def _is_dn(self, value: str) -> bool:
        """Check if value looks like a DN."""
        return "=" in value and ("," in value or value.count("=") == 1)

    def _is_boolean_text(self, value: str) -> bool:
        """Check if value is boolean text."""
        return value.lower() in {"true", "false", "yes", "no", "1", "0"}

    def _is_datetime(self, value: str) -> bool:
        """Check if value looks like a datetime."""
        # Simple datetime pattern matching
        datetime_patterns = [
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",  # ISO format with Z
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}",  # ISO format without Z
            r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}",  # SQL datetime format
        ]

        import re

        return any(re.match(pattern, value) for pattern in datetime_patterns)


# Backward compatibility
DataTypeConverter = FlextSimpleConverter

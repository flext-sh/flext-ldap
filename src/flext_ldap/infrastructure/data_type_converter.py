"""Data Type Converter - Refactored to eliminate ldap3 duplication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Simplified data type converter that uses ldap3's native type handling
for most operations, with minimal business-specific conversions only.
"""

from __future__ import annotations

# Re-export simplified converter components
from flext_ldap.infrastructure.simple_converter import (
    FlextLdapDataType,
    FlextSimpleConverter,
)

# Backward compatibility aliases for old naming
LDAPDataType = FlextLdapDataType
DataTypeConverter = FlextSimpleConverter

# For different test files, provide multiple aliases
FlextLdapDataTypeConverter = FlextSimpleConverter


# Error and result classes for test compatibility
class FlextLdapConversionError(Exception):
    """Conversion error exception."""


class ConversionError(Exception):
    """Conversion error exception."""


class FlextLdapConversionResult:
    """LDAP conversion result container."""

    def __init__(
        self,
        success: bool,
        data: object | None = None,
        error: str | None = None,
    ) -> None:
        """Initialize FlextLdapConversionResult."""
        self.success = success
        self.data = data
        self.error = error


class ConversionResult:
    """Simple conversion result container."""

    def __init__(
        self,
        success: bool,
        data: object | None = None,
        error: str | None = None,
    ) -> None:
        """Initialize ConversionResult."""
        self.success = success
        self.data = data
        self.error = error


__all__ = [
    "ConversionError",
    "ConversionResult",
    "DataTypeConverter",
    "FlextLdapConversionError",
    "FlextLdapConversionResult",
    "FlextLdapDataType",
    "FlextLdapDataTypeConverter",
    "LDAPDataType",
]

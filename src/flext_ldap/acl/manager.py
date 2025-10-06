"""ACL Manager for FLEXT LDAP.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_core import FlextHandlers, FlextResult, FlextTypes
from flext_ldap.acl.converters import FlextLdapAclConverters
from flext_ldap.acl.parsers import FlextLdapAclParsers


class FlextLdapAclManager(FlextHandlers[object, object]):
    """ACL Manager for comprehensive ACL operations."""

    def __init__(self) -> None:
        """Initialize ACL Manager."""
        # Initialize parsers and converters - unified classes without config
        self.parsers: FlextLdapAclParsers = FlextLdapAclParsers()
        self.converters: FlextLdapAclConverters = FlextLdapAclConverters()

    @override
    def handle(self, message: object) -> FlextResult[object]:
        """Handle ACL operations with proper type safety."""
        try:
            # Type-safe message handling
            if not isinstance(message, dict):
                return FlextResult[object].fail("Message must be a dictionary")

            operation = message.get("operation")
            if not isinstance(operation, str):
                return FlextResult[object].fail("Operation must be a string")

            # Route to appropriate handler based on operation
            if operation == "parse":
                return self._handle_parse(message)
            if operation == "convert":
                return self._handle_convert(message)
            return FlextResult[object].fail(f"Unknown operation: {operation}")

        except Exception as e:
            return FlextResult[object].fail(f"ACL operation failed: {e}")

    def _handle_parse(self, message: FlextTypes.Dict) -> FlextResult[object]:
        """Handle ACL parsing operations."""
        try:
            acl_string = message.get("acl_string")
            if not isinstance(acl_string, str):
                return FlextResult[object].fail("ACL string must be provided")

            format_type = message.get("format", "auto")
            if not isinstance(format_type, str):
                format_type = "auto"

            # Use parser to parse ACL based on format type
            if format_type == "openldap":
                result = self.parsers.OpenLdapAclParser.parse(acl_string)
            elif format_type == "oracle":
                result = self.parsers.OracleAclParser.parse(acl_string)
            elif format_type == "aci":
                result = self.parsers.AciParser.parse(acl_string)
            else:
                return FlextResult[object].fail(
                    f"Unsupported ACL format: {format_type}"
                )

            return FlextResult[object].ok(result)

        except Exception as e:
            return FlextResult[object].fail(f"ACL parsing failed: {e}")

    def _handle_convert(self, message: FlextTypes.Dict) -> FlextResult[object]:
        """Handle ACL conversion operations."""
        try:
            acl_data = message.get("acl_data")
            if not isinstance(acl_data, str):
                return FlextResult[object].fail("ACL data must be a string")

            target_format = message.get("target_format")
            if not isinstance(target_format, str):
                return FlextResult[object].fail("Target format must be specified")

            # Use converter to convert ACL
            source_format = message.get("source_format", "auto")
            if not isinstance(source_format, str):
                source_format = "auto"
            result = self.converters.convert_acl(acl_data, source_format, target_format)
            return FlextResult[object].ok(result)

        except Exception as e:
            return FlextResult[object].fail(f"ACL conversion failed: {e}")

    def parse_acl(self, acl_string: str, format_type: str) -> FlextResult[object]:
        """Parse ACL string using the specified format."""
        try:
            # Use parser to parse ACL based on format type
            if format_type == "openldap":
                result = self.parsers.OpenLdapAclParser.parse(acl_string)
            elif format_type == "oracle":
                result = self.parsers.OracleAclParser.parse(acl_string)
            elif format_type == "aci":
                result = self.parsers.AciParser.parse(acl_string)
            else:
                return FlextResult[object].fail(
                    f"Unsupported ACL format: {format_type}"
                )

            if result.is_success:
                return FlextResult[object].ok(result.unwrap())
            return FlextResult[object].fail(f"ACL parsing failed: {result.error}")
        except Exception as e:
            return FlextResult[object].fail(f"ACL parsing failed: {e}")

    def convert_acl(
        self, acl_data: str, source_format: str, target_format: str
    ) -> FlextResult[object]:
        """Convert ACL from one format to another."""
        try:
            result = self.converters.convert_acl(acl_data, source_format, target_format)
            if result.is_success:
                return FlextResult[object].ok(result.unwrap())
            return FlextResult[object].fail(f"ACL conversion failed: {result.error}")
        except Exception as e:
            return FlextResult[object].fail(f"ACL conversion failed: {e}")

    def batch_convert(
        self, acls: FlextTypes.StringList, source_format: str, target_format: str
    ) -> FlextResult[FlextTypes.List]:
        """Convert multiple ACLs from one format to another."""
        try:
            # Validate input is not empty
            if not acls:
                return FlextResult[FlextTypes.List].fail("ACL list cannot be empty")

            results = []
            for acl in acls:
                result = self.converters.convert_acl(acl, source_format, target_format)
                if result.is_failure:
                    return FlextResult[FlextTypes.List].fail(
                        f"Batch conversion failed for ACL '{acl}': {result.error}"
                    )
                # Unwrap the FlextResult to get the ConversionResult object
                results.append(result.unwrap())
            return FlextResult[FlextTypes.List].ok(results)
        except Exception as e:
            return FlextResult[FlextTypes.List].fail(
                f"Batch ACL conversion failed: {e}"
            )

    def validate_acl_syntax(
        self, acl_string: str, format_type: str
    ) -> FlextResult[bool]:
        """Validate ACL syntax for the specified format."""
        try:
            # Use parser to validate ACL syntax
            if format_type == "openldap":
                result = self.parsers.OpenLdapAclParser.parse(acl_string)
            elif format_type == "oracle":
                result = self.parsers.OracleAclParser.parse(acl_string)
            elif format_type == "aci":
                result = self.parsers.AciParser.parse(acl_string)
            else:
                return FlextResult[bool].fail(f"Unsupported ACL format: {format_type}")

            # If parsing succeeds, syntax is valid
            if result.is_success:
                return FlextResult[bool].ok(True)
            return FlextResult[bool].fail(f"Invalid ACL syntax: {result.error}")
        except Exception as e:
            return FlextResult[bool].fail(f"ACL syntax validation failed: {e}")


__all__ = ["FlextLdapAclManager"]

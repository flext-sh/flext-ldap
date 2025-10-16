"""ACL Manager for FLEXT LDAP.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextHandlers, FlextModels, FlextResult, FlextTypes

from flext_ldap.acl.converters import FlextLdapAclConverters
from flext_ldap.acl.parsers import FlextLdapAclParsers
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels


class FlextLdapAclManager(FlextHandlers[dict[str, object], FlextLdapModels.Acl]):
    """ACL Manager for comprehensive ACL operations."""

    def __init__(self) -> None:
        """Initialize ACL Manager."""
        # Create handler configuration for the base class
        config = FlextModels.Cqrs.Handler(
            handler_id="acl-manager",
            handler_name="FlextLdapAclManager",
            handler_type="command",
        )
        super().__init__(config=config)
        # Initialize parsers and converters - unified classes without config
        self._parsers: FlextLdapAclParsers = FlextLdapAclParsers()
        self._converters: FlextLdapAclConverters = FlextLdapAclConverters()

    def handle(
        self,
        message: dict[str, object],
    ) -> FlextResult[FlextLdapModels.Acl]:
        """Handle ACL operations with proper type safety."""
        try:
            # Type-safe request handling
            if not isinstance(message, dict):
                return FlextResult[FlextLdapModels.Acl].fail(
                    "Request must be a dictionary",
                )

            operation_raw = message.get(FlextLdapConstants.DictKeys.OPERATION)
            if not isinstance(operation_raw, str):
                return FlextResult[FlextLdapModels.Acl].fail(
                    "Operation must be a string",
                )
            operation: str = operation_raw

            # Route to appropriate handler based on operation
            if operation == FlextLdapConstants.LiteralTypes.OPERATION_PARSE:
                return self._handle_parse(message)
            if operation == FlextLdapConstants.LiteralTypes.OPERATION_CONVERT:
                return self._handle_convert(message)
            return FlextResult[FlextLdapModels.Acl].fail(
                f"Unknown operation: {operation}",
            )

        except Exception as e:
            return FlextResult[FlextLdapModels.Acl].fail(
                f"ACL operation failed: {e}",
            )

    def _handle_parse(
        self,
        message: dict[str, object],
    ) -> FlextResult[FlextLdapModels.Acl]:
        """Handle ACL parsing operations."""
        try:
            acl_string_raw = message.get(FlextLdapConstants.DictKeys.ACL_STRING)
            if not isinstance(acl_string_raw, str):
                return FlextResult[FlextLdapModels.Acl].fail(
                    "ACL string must be provided",
                )
            acl_string: str = acl_string_raw

            format_type_raw = message.get(
                FlextLdapConstants.DictKeys.FORMAT,
                FlextLdapConstants.AclFormat.AUTO,
            )
            final_format_type: str = (
                FlextLdapConstants.AclFormat.AUTO
                if not isinstance(format_type_raw, str)
                else format_type_raw
            )

            # Use parser to parse ACL based on format type
            if final_format_type == FlextLdapConstants.AclFormat.OPENLDAP:
                return self._parsers.OpenLdapAclParser.parse(acl_string)
            if final_format_type == FlextLdapConstants.AclFormat.ORACLE:
                return self._parsers.OracleAclParser.parse(acl_string)
            if final_format_type == FlextLdapConstants.AclFormat.ACI:
                return self._parsers.AciParser.parse(acl_string)
            return FlextResult[FlextLdapModels.Acl].fail(
                f"Unsupported ACL format: {final_format_type}",
            )

        except Exception as e:
            return FlextResult[FlextLdapModels.Acl].fail(
                f"ACL parsing failed: {e}",
            )

    def _handle_convert(
        self,
        message: dict[str, object],
    ) -> FlextResult[FlextLdapModels.Acl]:
        """Handle ACL conversion operations."""
        try:
            acl_data_raw = message.get(FlextLdapConstants.DictKeys.ACL_DATA)
            if not isinstance(acl_data_raw, str):
                return FlextResult[FlextLdapModels.Acl].fail(
                    "ACL data must be a string",
                )
            acl_data: str = acl_data_raw

            target_format_raw = message.get(FlextLdapConstants.DictKeys.TARGET_FORMAT)
            if not isinstance(target_format_raw, str):
                return FlextResult[FlextLdapModels.Acl].fail(
                    "Target format must be specified",
                )
            target_format: str = target_format_raw

            # Use converter to convert ACL
            source_format_raw = message.get(
                "source_format",
                FlextLdapConstants.AclFormat.AUTO,
            )
            final_source_format: str = (
                FlextLdapConstants.AclFormat.AUTO
                if not isinstance(source_format_raw, str)
                else source_format_raw
            )
            # Converter returns FlextResult[FlextLdapModels.Acl], return it directly
            return self._converters.convert_acl(
                acl_data, final_source_format, target_format
            )

        except Exception as e:
            return FlextResult[FlextLdapModels.Acl].fail(
                f"ACL conversion failed: {e}",
            )

    def parse_acl(
        self,
        acl_string: str,
        format_type: str,
    ) -> FlextResult[FlextLdapModels.Acl]:
        """Parse ACL string using the specified format."""
        try:
            # Use parser to parse ACL based on format type
            if format_type == FlextLdapConstants.AclFormat.OPENLDAP:
                result = self._parsers.OpenLdapAclParser.parse(acl_string)
            elif format_type == FlextLdapConstants.AclFormat.ORACLE:
                result = self._parsers.OracleAclParser.parse(acl_string)
            elif format_type == FlextLdapConstants.AclFormat.ACI:
                result = self._parsers.AciParser.parse(acl_string)
            else:
                return FlextResult[FlextLdapModels.Acl].fail(
                    f"Unsupported ACL format: {format_type}",
                )

            if result.is_success:
                return FlextResult[FlextLdapModels.Acl].ok(result.unwrap())
            return FlextResult[FlextLdapModels.Acl].fail(
                f"ACL parsing failed: {result.error}",
            )
        except Exception as e:
            return FlextResult[FlextLdapModels.Acl].fail(
                f"ACL parsing failed: {e}",
            )

    def convert_acl(
        self,
        acl_data: str,
        source_format: str,
        target_format: str,
    ) -> FlextResult[FlextLdapModels.Acl]:
        """Convert ACL from one format to another."""
        try:
            result = self._converters.convert_acl(
                acl_data,
                source_format,
                target_format,
            )
            if result.is_success:
                return FlextResult[FlextLdapModels.Acl].ok(result.unwrap())
            return FlextResult[FlextLdapModels.Acl].fail(
                f"ACL conversion failed: {result.error}",
            )
        except Exception as e:
            return FlextResult[FlextLdapModels.Acl].fail(
                f"ACL conversion failed: {e}",
            )

    def batch_convert(
        self,
        acls: FlextTypes.StringList,
        source_format: str,
        target_format: str,
    ) -> FlextResult[list[FlextLdapModels.Acl]]:
        """Convert multiple ACLs from one format to another."""
        try:
            # Validate input is not empty
            if not acls:
                return FlextResult[list[FlextLdapModels.Acl]].fail(
                    "ACL list cannot be empty"
                )

            results = []
            for acl in acls:
                result = self._converters.convert_acl(acl, source_format, target_format)
                if result.is_failure:
                    return FlextResult[list[FlextLdapModels.Acl]].fail(
                        f"Batch conversion failed for ACL '{acl}': {result.error}",
                    )
                # Unwrap the FlextResult to get the ConversionResult object
                results.append(result.unwrap())
            return FlextResult[list[FlextLdapModels.Acl]].ok(results)
        except Exception as e:
            return FlextResult[list[FlextLdapModels.Acl]].fail(
                f"Batch ACL conversion failed: {e}",
            )

    def validate_acl_syntax(
        self,
        acl_string: str,
        format_type: str,
    ) -> FlextResult[bool]:
        """Validate ACL syntax for the specified format."""
        try:
            # Use parser to validate ACL syntax
            if format_type == FlextLdapConstants.AclFormat.OPENLDAP:
                result = self._parsers.OpenLdapAclParser.parse(acl_string)
            elif format_type == FlextLdapConstants.AclFormat.ORACLE:
                result = self._parsers.OracleAclParser.parse(acl_string)
            elif format_type == FlextLdapConstants.AclFormat.ACI:
                result = self._parsers.AciParser.parse(acl_string)
            else:
                return FlextResult[bool].fail(f"Unsupported ACL format: {format_type}")

            # If parsing succeeds, syntax is valid
            if result.is_success:
                return FlextResult[bool].ok(True)
            return FlextResult[bool].fail(f"Invalid ACL syntax: {result.error}")
        except Exception as e:
            return FlextResult[bool].fail(f"ACL syntax validation failed: {e}")


__all__ = ["FlextLdapAclManager"]

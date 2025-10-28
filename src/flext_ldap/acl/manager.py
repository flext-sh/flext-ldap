"""ACL manager for FLEXT LDAP access control operations.

Manages ACL operations with parsing, conversion, and validation across
different LDAP server implementations (OpenLDAP, Oracle, AD).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextConstants, FlextHandlers, FlextModels, FlextResult
from flext_ldif import FlextLdifModels

from flext_ldap.acl.converters import FlextLdapAclConverters
from flext_ldap.acl.parsers import FlextLdapAclParsers
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.typings import LdapConfigDict


class FlextLdapAclManager(FlextHandlers[LdapConfigDict, FlextLdifModels.Acl]):
    """ACL Manager for ACL operations."""

    def __init__(self) -> None:
        """Initialize ACL Manager."""
        # Create handler configuration for the base class
        config = FlextModels.Cqrs.Handler(
            handler_id="acl-manager",
            handler_name="FlextLdapAclManager",
            handler_type=FlextConstants.Cqrs.HandlerType.COMMAND,
        )
        super().__init__(config=config)
        # Initialize parsers and converters - unified classes without config
        self._parsers: FlextLdapAclParsers = FlextLdapAclParsers()
        self._converters: FlextLdapAclConverters = FlextLdapAclConverters()

    def handle(
        self,
        message: LdapConfigDict,
    ) -> FlextResult[FlextLdifModels.Acl]:
        """Handle ACL operations with proper type safety."""
        try:
            # Type-safe request handling
            if not isinstance(message, dict):
                return FlextResult[FlextLdifModels.Acl].fail(
                    "Request must be a dictionary",
                )

            operation_raw = message.get(FlextLdapConstants.LdapDictKeys.OPERATION)
            if not isinstance(operation_raw, str):
                return FlextResult[FlextLdifModels.Acl].fail(
                    "Operation must be a string",
                )
            operation: str = operation_raw

            # Route to appropriate handler based on operation
            if operation == "parse":
                return self._handle_parse(message)
            if operation == "convert":
                return self._handle_convert(message)
            return FlextResult[FlextLdifModels.Acl].fail(
                f"Unknown operation: {operation}",
            )

        except Exception as e:
            return FlextResult[FlextLdifModels.Acl].fail(
                f"ACL operation failed: {e}",
            )

    def _handle_parse(
        self,
        message: LdapConfigDict,
    ) -> FlextResult[FlextLdifModels.Acl]:
        """Handle ACL parsing operations - delegates to flext-ldif."""
        try:
            acl_string_raw = message.get(FlextLdapConstants.LdapDictKeys.ACL_STRING)
            if not isinstance(acl_string_raw, str):
                return FlextResult[FlextLdifModels.Acl].fail(
                    "ACL string must be provided",
                )

            format_type_raw = message.get(
                FlextLdapConstants.LdapDictKeys.FORMAT,
                FlextLdapConstants.AclFormat.AUTO,
            )
            final_format_type: str = (
                FlextLdapConstants.AclFormat.AUTO
                if not isinstance(format_type_raw, str)
                else format_type_raw
            )

            # ACL parsing delegated to flext-ldif for proper FlextLdifModels integration
            return FlextResult[FlextLdifModels.Acl].fail(
                f"ACL parsing (format: {final_format_type}) deferred to flext-ldif. "
                "Use flext-ldif.FlextLdifParsers for server-specific ACL processing.",
            )

        except Exception as e:
            return FlextResult[FlextLdifModels.Acl].fail(
                f"ACL parsing failed: {e}",
            )

    def _handle_convert(
        self,
        message: LdapConfigDict,
    ) -> FlextResult[FlextLdifModels.Acl]:
        """Handle ACL conversion operations."""
        try:
            acl_data_raw = message.get(FlextLdapConstants.LdapDictKeys.ACL_DATA)
            if not isinstance(acl_data_raw, str):
                return FlextResult[FlextLdifModels.Acl].fail(
                    "ACL data must be a string",
                )
            acl_data: str = acl_data_raw

            target_format_raw = message.get(
                FlextLdapConstants.LdapDictKeys.TARGET_FORMAT
            )
            if not isinstance(target_format_raw, str):
                return FlextResult[FlextLdifModels.Acl].fail(
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
            # Converter returns FlextResult[FlextLdifModels.Acl], return it directly
            return self._converters.convert_acl(
                acl_data, final_source_format, target_format
            )

        except Exception as e:
            return FlextResult[FlextLdifModels.Acl].fail(
                f"ACL conversion failed: {e}",
            )

    def parse_acl(
        self,
        acl_string: str,  # noqa: ARG002 - parameter kept for API compatibility, delegated to flext-ldif
        format_type: str,
    ) -> FlextResult[FlextLdifModels.Acl]:
        """Parse ACL string using the specified format - delegates to flext-ldif."""
        try:
            # ACL parsing delegated to flext-ldif for proper FlextLdifModels integration
            return FlextResult[FlextLdifModels.Acl].fail(
                f"ACL parsing (format: {format_type}) deferred to flext-ldif. "
                "Use flext-ldif.FlextLdifParsers for server-specific ACL processing.",
            )
        except Exception as e:
            return FlextResult[FlextLdifModels.Acl].fail(
                f"ACL parsing failed: {e}",
            )

    def convert_acl(
        self,
        acl_data: str,
        source_format: str,
        target_format: str,
    ) -> FlextResult[FlextLdifModels.Acl]:
        """Convert ACL from one format to another."""
        try:
            result = self._converters.convert_acl(
                acl_data,
                source_format,
                target_format,
            )
            if result.is_success:
                return FlextResult[FlextLdifModels.Acl].ok(result.unwrap())
            return FlextResult[FlextLdifModels.Acl].fail(
                f"ACL conversion failed: {result.error}",
            )
        except Exception as e:
            return FlextResult[FlextLdifModels.Acl].fail(
                f"ACL conversion failed: {e}",
            )

    def batch_convert(
        self,
        acls: list[str],
        source_format: str,
        target_format: str,
    ) -> FlextResult[list[FlextLdifModels.Acl]]:
        """Convert multiple ACLs from one format to another."""
        try:
            # Validate input is not empty
            if not acls:
                return FlextResult[list[FlextLdifModels.Acl]].fail(
                    "ACL list cannot be empty"
                )

            results = []
            for acl in acls:
                result = self._converters.convert_acl(acl, source_format, target_format)
                if result.is_failure:
                    return FlextResult[list[FlextLdifModels.Acl]].fail(
                        f"Batch conversion failed for ACL '{acl}': {result.error}",
                    )
                # Unwrap the FlextResult to get the ConversionResult object
                results.append(result.unwrap())
            return FlextResult[list[FlextLdifModels.Acl]].ok(results)
        except Exception as e:
            return FlextResult[list[FlextLdifModels.Acl]].fail(
                f"Batch ACL conversion failed: {e}",
            )

    def validate_acl_syntax(
        self,
        acl_string: str,  # noqa: ARG002 - parameter kept for API compatibility, delegated to flext-ldif
        format_type: str,
    ) -> FlextResult[bool]:
        """Validate ACL syntax for the specified format - delegates to flext-ldif."""
        try:
            # ACL validation delegated to flext-ldif for proper FlextLdifModels integration
            return FlextResult[bool].fail(
                f"ACL syntax validation (format: {format_type}) deferred to flext-ldif. "
                "Use flext-ldif.FlextLdifParsers for server-specific validation.",
            )
        except Exception as e:
            return FlextResult[bool].fail(f"ACL syntax validation failed: {e}")


__all__ = ["FlextLdapAclManager"]

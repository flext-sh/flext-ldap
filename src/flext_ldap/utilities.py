"""LDAP-specific utility functions for the flext-ldap library.

This module provides LDAP-specific helper functions that build on top of
FlextUtilities from flext-core for operations specific to LDAP directory services.

Architecture:
    - Generic utilities: Use FlextUtilities from flext-core
    - LDAP-specific utilities: Use FlextLdapUtilities from this module

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re

from flext_core import (
    FlextDecorators,
    FlextLogger,
    FlextResult,
)
from flext_ldif import FlextLdifModels

from flext_ldap.constants import FlextLdapConstants

logger = FlextLogger(__name__)


class FlextLdapUtilities:
    """LDAP-specific utility functions for flext-ldap.

    Provides LDAP-specific helper functions organized by domain:
    - ServerDetection: Detect LDAP server type from root DSE attributes
    - AclFormatting: Format ACLs for server-specific syntax
    - ErrorHandling: LDAP error pattern detection
    - AttributeFiltering: Attribute filtering for LDAP operations
    - More namespaces to be added as helpers are consolidated

    For generic utilities (validation, generators, text processing, etc.),
    use FlextUtilities from flext-core.
    """

    class ErrorHandling:
        """LDAP error detection and handling utilities."""

        @staticmethod
        def is_already_exists_error(error: object) -> bool:
            """Check if error indicates entry already exists.

            Consolidated helper for Railway Pattern error detection.
            Checks for common LDAP "entry already exists" error patterns.

            Args:
                error: Error object to check

            Returns:
                True if error indicates entry already exists, False otherwise

            """
            error_msg = str(error).lower()
            return any(
                pattern in error_msg
                for pattern in [
                    FlextLdapConstants.ErrorPatterns.ENTRY_ALREADY_EXISTS,
                    FlextLdapConstants.ErrorPatterns.ALREADY_EXISTS,
                    FlextLdapConstants.ErrorPatterns.CODE_68,
                ]
            )

    class AttributeFiltering:
        """Attribute filtering utilities for LDAP operations."""

    class Validation:
        """LDAP-specific validation utilities for inputs and parameters."""

        @staticmethod
        def validate_required_string(
            param_name: str, value: object
        ) -> FlextResult[bool]:
            """Validate required string parameter.

            Args:
                param_name: Name of the parameter for error messages
                value: Value to validate

            Returns:
                FlextResult[bool] indicating validation success or failure

            """
            if value is None:
                return FlextResult[bool].fail(f"{param_name} cannot be None")
            if not isinstance(value, str) or (
                not isinstance(value, str) and bool(value.strip())
            ):
                return FlextResult[bool].fail(f"{param_name} cannot be empty")
            return FlextResult[bool].ok(True)

        @staticmethod
        def validate_non_negative_int(
            param_name: str, value: object
        ) -> FlextResult[bool]:
            """Validate non-negative integer parameter.

            Args:
                param_name: Name of the parameter for error messages
                value: Value to validate

            Returns:
                FlextResult[bool] indicating validation success or failure

            """
            if value is None:
                return FlextResult[bool].fail(f"{param_name} cannot be None")
            if not isinstance(value, int) or value < 0:
                return FlextResult[bool].fail(f"{param_name} must be non-negative")
            return FlextResult[bool].ok(True)

        @staticmethod
        def validate_password(param_name: str, value: object) -> FlextResult[bool]:
            """Validate password parameter.

            Args:
                param_name: Name of the parameter for error messages
                value: Value to validate

            Returns:
                FlextResult[bool] indicating validation success or failure

            """
            if value is None:
                return FlextResult[bool].fail(f"{param_name} cannot be None")
            if not isinstance(value, str):
                return FlextResult[bool].fail(f"{param_name} must be a string")

            pwd = value
            if len(pwd) < FlextLdapConstants.Validation.MIN_PASSWORD_LENGTH:
                return FlextResult[bool].fail(
                    f"{param_name} must be at least {FlextLdapConstants.Validation.MIN_PASSWORD_LENGTH} characters"
                )
            if len(pwd) > FlextLdapConstants.Validation.MAX_PASSWORD_LENGTH:
                return FlextResult[bool].fail(
                    f"{param_name} must be no more than {FlextLdapConstants.Validation.MAX_PASSWORD_LENGTH} characters"
                )
            return FlextResult[bool].ok(True)

        @staticmethod
        def validate_ldap_uri(param_name: str, value: object) -> FlextResult[bool]:
            """Validate LDAP URI parameter.

            Args:
                param_name: Name of the parameter for error messages
                value: Value to validate

            Returns:
                FlextResult[bool] indicating validation success or failure

            """
            if value is None:
                return FlextResult[bool].fail(f"{param_name} cannot be None")
            if not isinstance(value, str) or (
                not isinstance(value, str) and bool(value.strip())
            ):
                return FlextResult[bool].fail(f"{param_name} cannot be empty")

            uri_value = value.strip()
            if not re.match(
                FlextLdapConstants.RegexPatterns.SERVER_URI_PATTERN, uri_value
            ):
                return FlextResult[bool].fail(
                    f"{param_name} must start with ldap:// or ldaps://"
                )
            return FlextResult[bool].ok(True)

        @staticmethod
        def validate_ldap_filter(param_name: str, value: object) -> FlextResult[bool]:
            """Validate LDAP filter parameter.

            Args:
                param_name: Name of the parameter for error messages
                value: Value to validate

            Returns:
                FlextResult[bool] indicating validation success or failure

            """
            if value is None:
                return FlextResult[bool].fail(f"{param_name} cannot be None")
            if not isinstance(value, str) or (
                not isinstance(value, str) and bool(value.strip())
            ):
                return FlextResult[bool].fail(f"{param_name} cannot be empty")

            filter_value = value.strip()
            if not re.match(
                FlextLdapConstants.RegexPatterns.FILTER_PATTERN, filter_value
            ):
                return FlextResult[bool].fail(
                    f"{param_name} must be enclosed in parentheses"
                )
            return FlextResult[bool].ok(True)

        @staticmethod
        def validate_scope(scope: object) -> FlextResult[bool]:
            """Validate LDAP scope parameter using pattern matching.

            Args:
                scope: Scope value to validate

            Returns:
                FlextResult[bool] indicating validation success or failure

            """
            match scope:
                case None:
                    return FlextResult[bool].fail("Scope cannot be None")
                case str() as scope_value:
                    valid_scopes = FlextLdapConstants.ValidationSets.VALID_SCOPES
                    if scope_value.lower() not in valid_scopes:
                        scopes_str = ", ".join(sorted(valid_scopes))
                        return FlextResult[bool].fail(
                            f"Invalid scope: {scope_value}. Must be one of {scopes_str}"
                        )
                    return FlextResult[bool].ok(True)
                case _:
                    return FlextResult[bool].fail("Scope must be a string")

        @staticmethod
        def validate_modify_operation(operation: object) -> FlextResult[bool]:
            """Validate LDAP modify operation using pattern matching.

            Args:
                operation: Operation value to validate

            Returns:
                FlextResult[bool] indicating validation success or failure

            """
            match operation:
                case None:
                    return FlextResult[bool].fail("Operation cannot be None")
                case str() as op_value if op_value.lower() in {
                    "add",
                    "delete",
                    "replace",
                }:
                    return FlextResult[bool].ok(True)
                case str() as op_value:
                    valid_operations = {"add", "delete", "replace"}
                    ops_str = ", ".join(sorted(valid_operations))
                    return FlextResult[bool].fail(
                        f"Invalid operation: {op_value}. Must be one of {ops_str}"
                    )
                case _:
                    return FlextResult[bool].fail("Operation must be a string")

        @staticmethod
        def normalize_list_values(
            values_dict: dict[str, list[str] | str],
        ) -> dict[str, list[str]]:
            """Normalize dict values to always be lists.

            Converts dict[str, list[str] | str] → dict[str, list[str]]
            Useful for LDAP attribute normalization and similar scenarios.

            Args:
                values_dict: Dictionary with values as either strings or lists

            Returns:
                Dictionary with all values normalized to lists

            Example:
                >>> normalize_list_values({"a": "x", "b": ["y", "z"]})
                {"a": ["x"], "b": ["y", "z"]}

            """
            normalized: dict[str, list[str]] = {}
            for key, value in values_dict.items():
                if isinstance(value, list):
                    normalized[key] = value
                else:
                    normalized[key] = [value]
            return normalized

    class AclFormatting:
        """ACL formatting utilities for server-specific syntax."""

        @staticmethod
        def format_acls_for_server(
            acls: list[dict[str, object]],
            server_operations: object,
        ) -> FlextResult[list[str]]:
            """Format ACL dictionaries to server-specific ACL strings.

            Consolidated helper used by OID, OpenLDAP2, and OUD operations.
            Eliminates duplicate code across server implementations.

            Uses FlextUtilities.Validation for input validation and Railway Pattern.

            Args:
                acls: List of ACL dictionaries
                server_operations: Server operations instance with format_acl() method

            Returns:
                FlextResult containing list of formatted ACL strings or error

            """
            # Validate inputs using inline validation with FlextUtilities
            if not isinstance(acls, list) or not acls:
                return FlextResult[list[str]].fail("ACL list cannot be empty")

            if not hasattr(server_operations, "format_acl"):
                return FlextResult[list[str]].fail(
                    "Server operations must have format_acl method"
                )

            # Process ACLs using functional pipeline pattern
            formatted_acls: list[str] = []

            for acl in acls:
                # Validate individual ACL using FlextUtilities.TypeGuards
                if not isinstance(acl, dict) or not acl:
                    return FlextResult[list[str]].fail("ACL dictionary cannot be empty")

                # Convert dict to proper type (dict[str, str | list[str]])
                acl_dict: dict[str, str | list[str]] = {}
                for key, value in acl.items():
                    if isinstance(value, list):
                        acl_dict[key] = (
                            value
                            if all(isinstance(v, str) for v in value)
                            else [str(v) for v in value]
                        )
                    elif isinstance(value, str):
                        acl_dict[key] = value
                    else:
                        acl_dict[key] = [str(value)]

                # Create ACL entry
                acl_entry_result = FlextLdifModels.Entry.create(
                    dn=FlextLdapConstants.SyntheticDns.ACL_RULE,
                    attributes=acl_dict,
                )
                if acl_entry_result.is_failure:
                    return FlextResult[list[str]].fail(
                        f"Failed to create ACL entry: {acl_entry_result.error}",
                    )

                acl_entry = acl_entry_result.unwrap()

                # Delegate formatting to server-specific format_acl()
                format_result = server_operations.format_acl(acl_entry)
                if format_result.is_failure:
                    return FlextResult[list[str]].fail(
                        format_result.error or "ACL format failed",
                    )

                formatted_acls.append(format_result.unwrap())

            return FlextResult[list[str]].ok(formatted_acls)

    class ServerDetection:
        """Server type detection utilities from root DSE attributes."""

        @staticmethod
        def detect_oracle_server(root_dse: dict[str, object]) -> str | None:
            """Detect Oracle OID/OUD server from root DSE attributes.

            Args:
                root_dse: Root DSE attributes dictionary

            Returns:
                Server type string if Oracle detected, None otherwise

            """
            vendor_name = str(root_dse.get("vendorName", "")).lower()
            if FlextLdapConstants.VendorNames.ORACLE not in vendor_name:
                return None

            # Detect OUD vs OID from configContext
            config_context = str(root_dse.get("configContext", "")).lower()
            if FlextLdapConstants.SchemaDns.CONFIG.lower() in config_context:
                return FlextLdapConstants.ServerTypes.OUD

            return FlextLdapConstants.ServerTypes.OID

        @staticmethod
        def detect_openldap_server(root_dse: dict[str, object]) -> str | None:
            """Detect OpenLDAP 1.x or 2.x server from root DSE attributes.

            Args:
                root_dse: Root DSE attributes dictionary

            Returns:
                Server type string if OpenLDAP detected, None otherwise

            """
            vendor_name = str(root_dse.get("vendorName", "")).lower()
            if FlextLdapConstants.VendorNames.OPENLDAP not in vendor_name:
                return None

            # Detect version (1.x vs 2.x+)
            vendor_version = str(root_dse.get("vendorVersion", ""))
            if vendor_version.startswith(
                FlextLdapConstants.VersionPrefixes.VERSION_1_PREFIX,
            ):
                return FlextLdapConstants.ServerTypes.OPENLDAP1

            return FlextLdapConstants.ServerTypes.OPENLDAP2

        @staticmethod
        def detect_active_directory_server(
            root_dse: dict[str, object],
        ) -> str | None:
            """Detect Active Directory server from root DSE attributes.

            Args:
                root_dse: Root DSE attributes dictionary

            Returns:
                Server type string if Active Directory detected, None otherwise

            """
            # Check for AD-specific attributes
            has_root_domain = (
                FlextLdapConstants.RootDseAttributes.ROOT_DOMAIN_NAMING_CONTEXT
                in root_dse
            )
            has_default_naming = (
                FlextLdapConstants.RootDseAttributes.DEFAULT_NAMING_CONTEXT in root_dse
            )

            if has_root_domain or has_default_naming:
                return FlextLdapConstants.ServerTypes.AD

            return None

        @staticmethod
        def detect_oid_fallback(root_dse: dict[str, object]) -> str | None:
            """Detect Oracle OID as fallback when configContext attribute exists.

            Args:
                root_dse: Root DSE attributes dictionary

            Returns:
                Server type string if OID detected via fallback, None otherwise

            """
            if FlextLdapConstants.RootDseAttributes.CONFIG_CONTEXT in root_dse:
                return FlextLdapConstants.ServerTypes.OID

            return None

        @staticmethod
        @FlextDecorators.log_operation("LDAP Server Detection")
        @FlextDecorators.track_performance("LDAP Server Detection")
        def detect_server_type_from_root_dse(
            root_dse: dict[str, object],
        ) -> str:
            """Detect LDAP server type from root DSE attributes.

            Tries detection in order: Oracle, OpenLDAP, Active Directory, OID fallback.
            Returns generic type if no specific server detected.

            Uses FlextUtilities.Validation for robust input validation.

            Args:
                root_dse: Root DSE attributes dictionary

            Returns:
                Detected server type string

            """
            # Validate input using FlextUtilities.TypeGuards
            if not isinstance(root_dse, dict) or not root_dse:
                return FlextLdapConstants.Defaults.SERVER_TYPE

            # Detection pipeline using Railway Pattern
            detection_pipeline = [
                FlextLdapUtilities.ServerDetection.detect_oracle_server,
                FlextLdapUtilities.ServerDetection.detect_openldap_server,
                FlextLdapUtilities.ServerDetection.detect_active_directory_server,
                FlextLdapUtilities.ServerDetection.detect_oid_fallback,
            ]

            # Try each detection method in order
            for detector in detection_pipeline:
                try:
                    detected = detector(root_dse)
                    if detected:
                        return detected
                except (AttributeError, KeyError, TypeError, ValueError) as e:
                    # Continue to next detector on expected errors during detection
                    logger.debug(f"Detector {detector.__name__} failed: {e}")
                    continue

            # Generic fallback
            return FlextLdapConstants.Defaults.SERVER_TYPE


__all__ = [
    "FlextLdapUtilities",
]

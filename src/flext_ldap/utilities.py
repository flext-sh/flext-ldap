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

from flext_core import FlextResult
from flext_ldif import FlextLdifModels

from flext_ldap.constants import FlextLdapConstants


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

        @staticmethod
        def get_default_skip_attributes() -> set[str]:
            """Get default set of attributes to skip during UPSERT operations.

            Returns attributes that should never be modified:
            - Operational attributes (managed by server)
            - RDN attributes (cannot be modified via MODIFY)
            - Structural attributes (objectClass cannot be modified)

            Returns:
                Set of lowercase attribute names to skip

            """
            return {
                # Operational attributes
                "createtimestamp",
                "modifytimestamp",
                "creatorsname",
                "modifiersname",
                "entryuuid",
                "entrycsn",
                "structuralobjectclass",
                "hassubordinates",
                "subschemasubentry",
                # Common RDN attributes (check these, they're often RDNs)
                "cn",
                "uid",
                "ou",
                # Structural attributes (cannot be modified)
                "objectclass",
            }

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

            Args:
                acls: List of ACL dictionaries
                server_operations: Server operations instance with format_acl() method

            Returns:
                FlextResult containing list of formatted ACL strings or error

            """
            formatted_acls: list[str] = []

            for acl in acls:
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
                format_result = server_operations.format_acl(acl_entry)  # type: ignore[attr-defined]
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
            has_root_domain = FlextLdapConstants.RootDseAttributes.ROOT_DOMAIN_NAMING_CONTEXT in root_dse
            has_default_naming = FlextLdapConstants.RootDseAttributes.DEFAULT_NAMING_CONTEXT in root_dse

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
        def detect_server_type_from_root_dse(
            root_dse: dict[str, object],
        ) -> str:
            """Detect LDAP server type from root DSE attributes.

            Tries detection in order: Oracle, OpenLDAP, Active Directory, OID fallback.
            Returns generic type if no specific server detected.

            Args:
                root_dse: Root DSE attributes dictionary

            Returns:
                Detected server type string

            """
            # Try Oracle detection
            detected = FlextLdapUtilities.ServerDetection.detect_oracle_server(
                root_dse,
            )
            if detected:
                return detected

            # Try OpenLDAP detection
            detected = FlextLdapUtilities.ServerDetection.detect_openldap_server(
                root_dse,
            )
            if detected:
                return detected

            # Try Active Directory detection
            detected = FlextLdapUtilities.ServerDetection.detect_active_directory_server(
                root_dse,
            )
            if detected:
                return detected

            # Try OID fallback detection
            detected = FlextLdapUtilities.ServerDetection.detect_oid_fallback(root_dse)
            if detected:
                return detected

            # Generic fallback
            return FlextLdapConstants.Defaults.SERVER_TYPE


__all__ = [
    "FlextLdapUtilities",
]

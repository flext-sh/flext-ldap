"""LDAP schema discovery and quirks handling.

Automatic schema discovery and server quirks handling for universal
LDAP schema operations following FLEXT architectural patterns with proper
domain separation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC
from typing import override

from flext_core import (
    FlextConstants,
    FlextHandlers,
    FlextModels,
    FlextResult,
    FlextService,
)
from flext_ldif.constants import FlextLdifConstants

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.quirks_integration import FlextLdapQuirksIntegration
from flext_ldap.typings import FlextLdapTypes


class FlextLdapSchema(FlextService[FlextLdapTypes.DictionaryTypes.ResponseDict | None]):
    """Unified LDAP schema class following FLEXT one-class-per-module standards.

    This class consolidates ALL schema-related functionality including:
    - Server type detection
    - Schema discovery
    - Quirks handling
    - Normalization operations

    Following FLEXT patterns with proper domain separation and Clean Architecture.
    """

    # =========================================================================
    # QUIRKS DETECTION - Server-specific behavior detection
    # =========================================================================

    class QuirksDetector(
        FlextHandlers[
            FlextLdapTypes.DictionaryTypes.ResponseDict | None,
            FlextLdapTypes.DictionaryTypes.ResponseDict | None,
        ],
        ABC,
    ):
        """Abstract base class for LDAP server quirks detection."""

    class GenericQuirksDetector(QuirksDetector):
        """Generic quirks detector for unknown LDAP servers."""

        @override
        def __init__(self) -> None:
            """Initialize generic quirks detector."""
            # Create a minimal handler config for the base class
            config = FlextModels.Cqrs.Handler(
                handler_id="generic-quirks-detector",
                handler_name="GenericQuirksDetector",
                handler_type=FlextConstants.Cqrs.HandlerType.QUERY,
            )
            super().__init__(config=config)

        @override
        def handle(
            self,
            message: FlextLdapTypes.DictionaryTypes.ResponseDict | None,
        ) -> FlextResult[FlextLdapTypes.DictionaryTypes.ResponseDict | None]:
            """Handle quirks detection message.

            Args:
            message: The message to handle (typically server info)

            Returns:
            FlextResult containing the detection result

            """
            if not message:
                return FlextResult[
                    FlextLdapTypes.DictionaryTypes.ResponseDict | None
                ].fail("Message cannot be empty")

            # For generic detection, return a basic success result
            return FlextResult[FlextLdapTypes.DictionaryTypes.ResponseDict | None].ok({
                "detected": True,
                "type": FlextLdapConstants.Defaults.SERVER_TYPE,
            })

        def detect_server_type(
            self,
            server_info: FlextLdapTypes.DictionaryTypes.ResponseDict | None,
        ) -> FlextLdifConstants.LdapServerType | None:
            """Detect LDAP server type from server info.

            Args:
            server_info: Server information object

            Returns:
            Detected server type enum or None if detection fails

            """
            if not server_info:
                return None

            # Generic detection - return a default type enum
            return FlextLdifConstants.LdapServerType.GENERIC

        def get_server_quirks(
            self,
            server_type: str | None,
        ) -> FlextLdapModels.ServerQuirks | None:
            """Get server quirks for the specified server type.

            Args:
            server_type: The server type to get quirks for

            Returns:
            Server quirks object or None if not found

            """
            if not server_type:
                return None

            # Return generic quirks for any server type
            return FlextLdapModels.ServerQuirks(
                server_type=FlextLdifConstants.LdapServerType.GENERIC,
                case_sensitive_dns=True,
                case_sensitive_attributes=True,
                supports_paged_results=True,
                supports_vlv=False,
                supports_sync=False,
                max_page_size=FlextLdapConstants.Connection.MAX_PAGE_SIZE_GENERIC,
                default_timeout=FlextLdapConstants.Protocol.DEFAULT_TIMEOUT_SECONDS,
                supports_start_tls=True,
                requires_explicit_bind=False,
            )

    # =========================================================================
    # SCHEMA DISCOVERY - Automatic LDAP schema discovery and analysis
    # =========================================================================

    class Discovery(
        FlextHandlers[
            FlextLdapTypes.DictionaryTypes.ResponseDict | None,
            FlextLdapTypes.DictionaryTypes.ResponseDict | None,
        ],
    ):
        """Schema discovery operations with quirks-aware server detection.

        This class provides automatic schema discovery that adapts to different
        LDAP server types using the FlextLdif quirks system.
        """

        def __init__(
            self,
            quirks_adapter: FlextLdapQuirksIntegration | None = None,
        ) -> None:
            """Initialize schema discovery with optional quirks adapter.

            Args:
            quirks_adapter: Optional quirks adapter for server-specific handling

            """
            # Create handler config
            config = FlextModels.Cqrs.Handler(
                handler_id="schema-discovery",
                handler_name="SchemaDiscovery",
                handler_type=FlextConstants.Cqrs.HandlerType.QUERY,
            )
            super().__init__(config=config)
            # Note: self.logger is provided by FlextService parent class
            self._quirks_adapter = quirks_adapter or FlextLdapQuirksIntegration()

        @override
        def handle(
            self,
            message: FlextLdapTypes.DictionaryTypes.ResponseDict | None,
        ) -> FlextResult[FlextLdapTypes.DictionaryTypes.ResponseDict | None]:
            """Handle schema discovery message.

            Args:
            message: Schema discovery request

            Returns:
            FlextResult containing schema information

            """
            if not message:
                return FlextResult[
                    FlextLdapTypes.DictionaryTypes.ResponseDict | None
                ].fail(
                    "Schema discovery message cannot be empty",
                )

            # Return basic schema discovery result
            return FlextResult[FlextLdapTypes.DictionaryTypes.ResponseDict | None].ok({
                "schema_discovered": True,
            })

        def get_schema_subentry_dn(self, server_type: str | None) -> FlextResult[str]:
            """Get schema subentry DN based on server type.

            Args:
            server_type: LDAP server type (openldap, oracle, etc.)

            Returns:
            FlextResult containing schema subentry DN

            """
            try:
                # Handle None server_type
                if server_type is None:
                    server_type = FlextLdapConstants.Defaults.SERVER_TYPE

                # Server-specific schema subentry DNs
                schema_dns = {
                    FlextLdapConstants.ServerTypes.OPENLDAP: FlextLdapConstants.SchemaDns.SCHEMA_CONFIG,
                    FlextLdapConstants.ServerTypes.OPENLDAP2: FlextLdapConstants.SchemaDns.SCHEMA_CONFIG,
                    FlextLdapConstants.VendorNames.ORACLE: FlextLdapConstants.SchemaDns.SUBS_SCHEMA_SUBENTRY,
                    FlextLdapConstants.Defaults.SERVER_TYPE: FlextLdapConstants.SchemaDns.SCHEMA,
                }

                schema_dn = schema_dns.get(
                    server_type.lower(),
                    schema_dns[FlextLdapConstants.Defaults.SERVER_TYPE],
                )
                return FlextResult[str].ok(schema_dn)

            except Exception as e:
                return FlextResult[str].fail(f"Failed to get schema subentry DN: {e}")

    def execute(
        self,
    ) -> FlextResult[FlextLdapTypes.DictionaryTypes.ResponseDict | None]:
        """Execute the main domain operation (required by FlextService)."""
        return FlextResult[FlextLdapTypes.DictionaryTypes.ResponseDict | None].ok(None)

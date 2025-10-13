"""LDAP Schema Discovery and Quirks Handling for Universal Compatibility.

This module provides automatic schema discovery and handling of LDAP server
quirks to ensure compatibility with any LDAP implementation following
FLEXT architectural patterns with proper domain separation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC
from typing import override

from flext_core import FlextCore

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.quirks_integration import FlextLdapQuirksIntegration


class FlextLdapSchema(FlextCore.Service[FlextCore.Result[object]]):
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

    class QuirksDetector(FlextCore.Handlers[object, object], ABC):
        """Abstract base class for LDAP server quirks detection."""

    class GenericQuirksDetector(QuirksDetector):
        """Generic quirks detector for unknown LDAP servers."""

        @override
        def __init__(self) -> None:
            """Initialize generic quirks detector."""
            # Create a minimal handler config for the base class
            config = FlextCore.Models.Cqrs.Handler()
            config.handler_type = "query"
            config.default_name = "GenericQuirksDetector"
            config.default_id = "generic-quirks-detector"
            super().__init__(config=config)

        def handle(self, message: object) -> FlextCore.Result[object]:
            """Handle quirks detection message.

            Args:
                message: The message to handle (typically server info)

            Returns:
                FlextCore.Result containing the detection result

            """
            if not message:
                return FlextCore.Result[object].fail("Message cannot be empty")

            # For generic detection, return a basic success result
            return FlextCore.Result[object].ok({"detected": True, "type": "generic"})

        def detect_server_type(
            self,
            server_info: object,
        ) -> FlextLdapModels.LdapServerType | None:
            """Detect LDAP server type from server info.

            Args:
                server_info: Server information object

            Returns:
                Detected server type enum or None if detection fails

            """
            if not server_info:
                return None

            # Generic detection - return a default type enum
            return FlextLdapModels.LdapServerType.GENERIC

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
                server_type=FlextLdapModels.LdapServerType.GENERIC,
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

    class Discovery(FlextCore.Handlers[object, object]):
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
            config = FlextCore.Models.Cqrs.Handler()
            config.handler_type = "query"
            config.default_name = "SchemaDiscovery"
            config.default_id = "schema-discovery"
            super().__init__(config=config)
            # Note: self.logger is provided by FlextCore.Service parent class
            self._quirks_adapter = quirks_adapter or FlextLdapQuirksIntegration()

        @override
        def handle(self, message: object) -> FlextCore.Result[object]:
            """Handle schema discovery message.

            Args:
                message: Schema discovery request

            Returns:
                FlextCore.Result containing schema information

            """
            if not message:
                return FlextCore.Result[object].fail(
                    "Schema discovery message cannot be empty",
                )

            # Return basic schema discovery result
            return FlextCore.Result[object].ok({"schema_discovered": True})

        def get_schema_subentry_dn(
            self,
            server_type: str | None = None,
        ) -> FlextCore.Result[str]:
            """Get schema subentry DN based on server type.

            Uses quirks adapter to determine the correct schema endpoint for
            different server types (cn=subschema, cn=schema, etc.).

            Args:
                server_type: LDAP server type (detected if not provided)

            Returns:
                FlextCore.Result containing schema subentry DN

            """
            return self._quirks_adapter.get_schema_subentry(server_type)

    def execute(self) -> FlextCore.Result[object]:
        """Execute the main domain operation (required by FlextCore.Service)."""
        return FlextCore.Result[object].ok(None)

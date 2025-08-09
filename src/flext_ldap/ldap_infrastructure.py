"""LDAP Infrastructure - Compatibility Facade.

⚠️  DEPRECATED MODULE - Compatibility facade for migration

    MIGRATE TO: flext_ldap.infrastructure.ldap_client module
    REASON: SOLID refactoring - better separation of concerns

    NEW SOLID ARCHITECTURE:
    - LdapConnectionService: Connection management only (SRP)
    - LdapSearchService: Search operations only (SRP)
    - LdapWriteService: Write operations only (SRP)
    - FlextLdapClient: Composite client (DIP)

    OLD: from flext_ldap.ldap_infrastructure import FlextLdapSimpleClient
    NEW: from flext_ldap.infrastructure.ldap_client import FlextLdapClient

This module provides backward compatibility during the SOLID refactoring transition.
All functionality has been migrated to the new SOLID-compliant architecture in infrastructure/ldap_client.py.

The new architecture follows SOLID principles:
- Single Responsibility: Each service has one clear purpose
- Open/Closed: Extensible through composition, not modification
- Liskov Substitution: Perfect substitutability of implementations
- Interface Segregation: Focused protocols, no fat interfaces
- Dependency Inversion: High-level modules depend on abstractions

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING

from flext_core import FlextResult
from pydantic import BaseModel, Field

from flext_ldap.constants import FlextLdapScope
from flext_ldap.value_objects import FlextLdapDistinguishedName, FlextLdapFilter

if TYPE_CHECKING:
    from flext_core import FlextContainer

# Import the new SOLID implementation
from flext_ldap.infrastructure.ldap_client import FlextLdapClient, create_ldap_client

# Issue deprecation warning
warnings.warn(
    "🚨 DEPRECATED MODULE: ldap_infrastructure.py is deprecated.\n"
    "✅ MIGRATE TO: flext_ldap.infrastructure.ldap_client module\n"
    "🏗️ NEW ARCHITECTURE: SOLID-compliant services with clear separation\n"
    "📖 Migration guide available in module documentation\n"
    "⏰ This compatibility layer will be removed in v2.0.0",
    DeprecationWarning,
    stacklevel=2,
)


# ===== ADVANCED PYDANTIC TYPES FOR TYPE SAFETY =====


class LdapAuthConfig(BaseModel):
    """Advanced Pydantic model for LDAP authentication configuration."""

    server_url: str | None = Field(None, description="LDAP server URL")
    host: str = Field(default="localhost", description="LDAP server host")
    bind_dn: str | None = Field(None, description="Bind DN for authentication")
    username: str | None = Field(None, description="Username for authentication")
    password: str | None = Field(None, description="Password for authentication")
    port: int = Field(default=389, description="LDAP server port")
    use_ssl: bool = Field(default=False, description="Use SSL/TLS connection")

    model_config = {"extra": "allow"}  # Python 3.13 Pydantic v2 syntax


class LdapEntryAttributes(BaseModel):
    """Advanced Pydantic model for LDAP entry attributes."""

    object_class: list[str] = Field(default_factory=list, description="Object classes")
    cn: str | None = Field(None, description="Common name")
    sn: str | None = Field(None, description="Surname")
    uid: str | None = Field(None, description="User ID")
    mail: str | None = Field(None, description="Email address")

    model_config = {"extra": "allow"}  # Allow additional attributes


class FlextLdapSimpleClient(FlextLdapClient):
    """Compatibility facade for FlextLdapSimpleClient.

    ⚠️  DEPRECATED: Use FlextLdapClient from ldap_client module instead.

    This class provides backward compatibility for existing code that uses
    FlextLdapSimpleClient. All functionality has been migrated to the new
    SOLID-compliant architecture.

    Migration Path:
        OLD: FlextLdapSimpleClient()
        NEW: FlextLdapClient()

    The new client provides the same interface but with better:
        - Testability (protocol-based design)
        - Maintainability (single responsibility services)
        - Extensibility (composition over inheritance)
        - Type safety (strict protocol contracts)
    """

    def __init__(self, container: FlextContainer | None = None) -> None:
        """Initialize with backward compatibility warning."""
        warnings.warn(
            "🚨 DEPRECATED CLASS: FlextLdapSimpleClient is deprecated.\n"
            "✅ USE INSTEAD: FlextLdapClient from flext_ldap.infrastructure.ldap_client\n"
            "🏗️ BENEFITS: SOLID principles, better testability, cleaner architecture\n"
            "📖 Same interface, improved implementation\n"
            "⏰ Will be removed in v2.0.0",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(container)
        self._current_connection_id: str | None = None

    # ===== OLD API COMPATIBILITY METHODS =====

    async def connect_with_auth(self, auth_config: LdapAuthConfig) -> FlextResult[str]:
        """Old API compatibility: connect with auth config object."""
        try:
            # Extract connection details from auth config
            server_url = getattr(auth_config, "server_url", None) or getattr(
                auth_config,
                "host",
                "localhost",
            )
            bind_dn = getattr(auth_config, "bind_dn", None) or getattr(
                auth_config,
                "username",
                None,
            )
            password = getattr(auth_config, "password", None)

            # Handle different config formats with null checks
            if hasattr(auth_config, "get_secret_value"):
                password = auth_config.get_secret_value()
            elif password is not None and hasattr(password, "get_secret_value"):
                password = password.get_secret_value()

            # Build server URL if needed with null check
            if server_url and not server_url.startswith(("ldap://", "ldaps://")):
                port = getattr(auth_config, "port", 389)
                use_ssl = getattr(auth_config, "use_ssl", False)
                protocol = "ldaps" if use_ssl else "ldap"
                server_url = f"{protocol}://{server_url}:{port}"

            if server_url is None:
                return FlextResult.fail("Server URL is required")
            result = await super().connect(server_url, bind_dn, password)
            if result.is_success:
                self._current_connection_id = result.data
            return result
        except Exception as e:
            return FlextResult.fail(f"Failed to connect with auth config: {e}")

    async def connect(self, *args: object) -> FlextResult[str]:
        """Old API compatibility: connect with various argument formats."""
        if len(args) == 1:
            # Single config object
            config = args[0]
            return await self.connect_with_auth(config)
        # Standard format
        return await super().connect(*args)

    async def disconnect(self, connection_id: str | None = None) -> FlextResult[None]:
        """Old API compatibility: disconnect with optional connection_id."""
        conn_id = connection_id or self._current_connection_id
        if conn_id:
            result = await super().disconnect(conn_id)
            # Convert from FlextResult[None] to FlextResult[None]
            if result.is_success:
                self._current_connection_id = None
                return FlextResult.ok(None)
            return FlextResult.fail(result.error or "Disconnect failed")
        return FlextResult.ok(None)

    async def add(self, dn: str, attributes: dict[str, list[str]], **_kwargs: object) -> FlextResult[None]:
        """Old API compatibility: add entry."""
        if not self._current_connection_id:
            return FlextResult.fail("No active connection")

        # Convert string DN to FlextLdapDistinguishedName
        dn_result = FlextLdapDistinguishedName.create(str(dn))
        if not dn_result.is_success:
            return FlextResult.fail(dn_result.error or "Invalid DN")

        if dn_result.data is None:
            return FlextResult.fail("Failed to create DN object")

        return await self.create_entry(
            self._current_connection_id,
            dn_result.data,
            attributes,
        )

    async def modify(self, dn: str, changes: dict[str, object], **_kwargs: object) -> FlextResult[None]:
        """Old API compatibility: modify entry."""
        if not self._current_connection_id:
            return FlextResult.fail("No active connection")

        # Convert string DN to FlextLdapDistinguishedName
        dn_result = FlextLdapDistinguishedName.create(str(dn))
        if not dn_result.is_success:
            return FlextResult.fail(dn_result.error or "Invalid DN")

        if dn_result.data is None:
            return FlextResult.fail("Failed to create DN object")

        return await self.modify_entry(
            self._current_connection_id,
            dn_result.data,
            changes,
        )

    async def delete(self, dn: str, **_kwargs: object) -> FlextResult[None]:
        """Old API compatibility: delete entry."""
        if not self._current_connection_id:
            return FlextResult.fail("No active connection")

        # Convert string DN to FlextLdapDistinguishedName
        dn_result = FlextLdapDistinguishedName.create(str(dn))
        if not dn_result.is_success:
            return FlextResult.fail(dn_result.error or "Invalid DN")

        if dn_result.data is None:
            return FlextResult.fail("Failed to create DN object")

        return await self.delete_entry(self._current_connection_id, dn_result.data)

    def _validate_search_params(
        self,
        base_dn: str,
        search_filter: str,
    ) -> FlextResult[tuple[FlextLdapDistinguishedName, FlextLdapFilter]]:
        """Validate search parameters using Railway-Oriented Programming."""
        # Chain validation operations
        dn_result = FlextLdapDistinguishedName.create(base_dn)
        if not dn_result.is_success:
            return FlextResult.fail(dn_result.error or "Invalid base DN")

        if dn_result.data is None:
            return FlextResult.fail("Failed to create DN object")

        filter_result = FlextLdapFilter.create(search_filter)
        if not filter_result.is_success:
            return FlextResult.fail(filter_result.error or "Invalid search filter")

        if filter_result.data is None:
            return FlextResult.fail("Failed to create filter object")

        return FlextResult.ok((dn_result.data, filter_result.data))

    async def search_old_api(
        self,
        base_dn: str,
        search_filter: str | None = None,
        attributes: list[str] | None = None,
        scope: str = "sub",
        **_kwargs: object,
    ) -> FlextResult[list[dict[str, str | list[str]]]]:
        """Old API compatibility: search with string parameters."""
        # Early validation - single return path
        if not self._current_connection_id:
            return FlextResult.fail("No active connection")

        # Handle different parameter formats
        if isinstance(base_dn, str) and isinstance(search_filter, str):
            # Use validation pipeline
            validation_result = self._validate_search_params(base_dn, search_filter)
            if not validation_result.is_success:
                return FlextResult.fail(validation_result.error or "Validation failed")

            if validation_result.data is None:
                return FlextResult.fail("Validation succeeded but no data returned")

            dn_obj, filter_obj = validation_result.data

            # Convert scope string to enum
            scope_enum = FlextLdapScope.SUB  # default
            if isinstance(scope, str):
                scope_map = {
                    "base": FlextLdapScope.BASE,
                    "one": FlextLdapScope.ONE,
                    "sub": FlextLdapScope.SUB,
                    "children": FlextLdapScope.CHILDREN,
                }
                scope_enum = scope_map.get(scope, FlextLdapScope.SUB)

            # Single return path for old API
            return await super().search(
                self._current_connection_id,
                dn_obj,
                filter_obj,
                scope_enum,
                attributes,
            )

        # Single return path for new API
        return await super().search(
            base_dn,
            search_filter,
            attributes,
            scope,
            **_kwargs,
        )

    async def search(
        self,
        connection_id: str | None = None,  # Optional for backward compatibility
        base_dn: str | None = None,
        search_filter: str | None = None,
        scope: str = "sub",
        attributes: list[str] | None = None,
        **_kwargs: object,
    ) -> FlextResult[list[dict[str, str | list[str]]]]:
        """Compatibility wrapper for old search API - matches parent signature."""
        # For backward compatibility, support both signatures
        if connection_id is None:
            # Old signature: search(base_dn, search_filter, attributes, scope)
            return await self.search_old_api(
                base_dn,
                search_filter,
                attributes,
                scope,
                **_kwargs,
            )
        # New signature: search(connection_id, base_dn, search_filter, scope, attributes)
        # Convert parameters to proper types for parent method call
        return await super().search(
            connection_id,
            base_dn,
            search_filter,
            scope,
            attributes,
        )


# Backward compatibility exports
__all__ = [
    "FlextLdapClient",  # Re-export new implementation
    "FlextLdapSimpleClient",
    "create_ldap_client",  # Re-export factory function
]

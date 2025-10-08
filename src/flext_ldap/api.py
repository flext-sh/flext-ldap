"""FlextLdap - Thin facade for LDAP operations with FLEXT integration.

Enterprise LDAP operations facade following FLEXT Clean Architecture patterns.
Provides unified access to LDAP domain functionality with proper delegation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import override

from flext_core import (
    FlextResult,
    FlextService,
    FlextTypes,
)
from flext_ldif import FlextLdif

from flext_ldap.clients import FlextLdapClients
from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.services import FlextLdapServices


class FlextLdap(FlextService[None]):
    """Thin facade for LDAP operations with FLEXT ecosystem integration.

    Provides unified access to LDAP domain functionality through proper delegation
    to specialized services and infrastructure components.

    **THIN FACADE PATTERN**: Minimal orchestration, delegates to domain services:
    - FlextLdapServices: Application services for LDAP operations
    - FlextLdapClients: Infrastructure LDAP client operations
    - FlextLdapValidations: Domain validation logic

    **USAGE**:
    - Use FlextLdap for core LDAP orchestration
    - Import specialized services directly for advanced operations
    - Import FlextLdapModels, FlextLdapConstants directly for domain access
    """

    @override
    def __init__(self, config: FlextLdapConfig | None = None) -> None:
        """Initialize LDAP facade with configuration."""
        super().__init__()
        self._config: FlextLdapConfig = config or FlextLdapConfig()
        self._services: FlextLdapServices | None = None
        self._client: FlextLdapClients | None = None

    @override
    def execute(self) -> FlextResult[None]:
        """Execute the main domain operation (required by FlextService)."""
        return FlextResult[None].ok(None)

    # =========================================================================
    # CORE FACADE METHODS - Thin delegation layer
    # =========================================================================

    @property
    def services(self) -> FlextLdapServices:
        """Get the LDAP services instance."""
        if self._services is None:
            self._services = FlextLdapServices()
        return self._services

    @property
    def client(self) -> FlextLdapClients:
        """Get the LDAP client instance."""
        if self._client is None:
            self._client = FlextLdapClients()
        return self._client

    @property
    def config(self) -> FlextLdapConfig:
        """Get the LDAP configuration."""
        return self._config

    # =========================================================================
    # CONNECTION MANAGEMENT - Delegate to client
    # =========================================================================

    def is_connected(self) -> bool:
        """Check if LDAP client is connected."""
        return self.client.is_connected()

    def connect(
        self,
        server: str | None = None,
        port: int | None = None,
        *,
        use_ssl: bool = False,
        bind_dn: str | None = None,
        bind_password: str | None = None,
    ) -> FlextResult[bool]:
        """Connect to LDAP server."""
        # Construct server URI from components
        if server is None:
            server = "localhost"
        if port is None:
            port = 636 if use_ssl else 389

        protocol = "ldaps" if use_ssl else "ldap"
        server_uri = f"{protocol}://{server}:{port}"

        # Validate required parameters
        if bind_dn is None or bind_password is None:
            return FlextResult[bool].fail("bind_dn and bind_password are required")

        return self.client.connect(server_uri, bind_dn, bind_password)

    def test_connection(self) -> FlextResult[bool]:
        """Test LDAP connection."""
        return self.client.test_connection()

    def unbind(self) -> FlextResult[None]:
        """Unbind from LDAP server."""
        return self.client.unbind()

    # =========================================================================
    # CORE LDAP OPERATIONS - Consolidated facade methods
    # =========================================================================

    def search(
        self,
        search_request: FlextLdapModels.SearchRequest,
    ) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Perform LDAP search operation.

        Args:
            search_request: Search request model with parameters

        Returns:
            FlextResult containing list of entries

        """
        return self.client.search_with_request(search_request).map(
            lambda response: response.entries
        )

    def add_entry(
        self, dn: str, attributes: dict[str, str | FlextTypes.StringList]
    ) -> FlextResult[bool]:
        """Add new LDAP entry.

        Args:
            dn: Distinguished name for new entry
            attributes: Entry attributes

        Returns:
            FlextResult indicating success

        """
        return self.client.add_entry(dn, attributes)

    def modify_entry(self, dn: str, changes: FlextTypes.Dict) -> FlextResult[bool]:
        """Modify existing LDAP entry.

        Args:
            dn: Distinguished name of entry to modify
            changes: Attribute changes to apply

        Returns:
            FlextResult indicating success

        """
        return self.client.modify_entry(dn, changes)

    def delete_entry(self, dn: str) -> FlextResult[bool]:
        """Delete LDAP entry.

        Args:
            dn: Distinguished name of entry to delete

        Returns:
            FlextResult indicating success

        """
        return self.client.delete_entry(dn)

    def authenticate_user(self, username: str, password: str) -> FlextResult[bool]:
        """Authenticate user against LDAP.

        Args:
            username: Username for authentication
            password: Password for authentication

        Returns:
            FlextResult indicating success

        """
        auth_result = self.client.authenticate_user(username, password)
        if auth_result.is_failure:
            return FlextResult[bool].fail(auth_result.error or "Authentication failed")
        return FlextResult[bool].ok(True)

    # =========================================================================
    # LDIF INTEGRATION - Delegate to flext-ldif
    # =========================================================================

    @property
    def ldif(self) -> FlextLdif:
        """Get LDIF processing instance."""
        if self._ldif is None:
            self._ldif = FlextLdif()
        return self._ldif

    def import_from_ldif(self, path: Path) -> FlextResult[list[FlextLdapModels.Entry]]:
        """Import entries from LDIF file.

        Args:
            path: Path to LDIF file

        Returns:
            FlextResult containing list of entries

        """
        result = self.ldif.parse(path)
        if result.is_failure:
            return FlextResult[list[FlextLdapModels.Entry]].fail(
                f"LDIF parsing failed: {result.error}"
            )

        ldif_entries = result.unwrap() or []
        ldap_entries = [
            FlextLdapModels.Entry.from_ldif(ldif_entry) for ldif_entry in ldif_entries
        ]

        return FlextResult[list[FlextLdapModels.Entry]].ok(ldap_entries)

    def export_to_ldif(
        self, entries: list[FlextLdapModels.Entry], path: Path
    ) -> FlextResult[bool]:
        """Export entries to LDIF file.

        Args:
            entries: List of LDAP entries to export
            path: Path to output LDIF file

        Returns:
            FlextResult indicating success

        """
        ldif_entries = [entry.to_ldif() for entry in entries]
        result = self.ldif.write(ldif_entries, path)
        if result.is_failure:
            return FlextResult[bool].fail(f"LDIF writing failed: {result.error}")

        return FlextResult[bool].ok(True)


__all__ = [
    "FlextLdap",
]

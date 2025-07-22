"""Directory Service Adapter - Implements flext-core DirectoryServiceInterface.

This adapter bridges the flext-core abstract domain interface with
the concrete FLEXT LDAP infrastructure implementation.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from flext_core.application.interfaces.directory_services import (
        DirectoryConnectionProtocol,
        DirectoryEntryProtocol,
    )
    from flext_core.domain.shared_types import ServiceResult

from flext_core.application.interfaces.directory_services import (
    DirectoryAdapterInterface,
    DirectoryServiceInterface,
)

from flext_ldap.infrastructure.ldap_client import LDAPInfrastructureClient


class FlextLDAPDirectoryService(DirectoryServiceInterface):
    """Concrete implementation of DirectoryServiceInterface using FLEXT LDAP."""

    def __init__(self) -> None:
        """Initialize FLEXT LDAP directory service."""
        self._ldap_client = LDAPInfrastructureClient()

    async def connect(
        self,
        connection_config: DirectoryConnectionProtocol,
    ) -> ServiceResult[str]:
        """Establish connection to directory server using FLEXT LDAP.

        Args:
            connection_config: Directory connection configuration

        Returns:
            ServiceResult containing connection ID or error

        """
        try:
            # Build server URI
            protocol = "ldaps" if connection_config.use_ssl else "ldap"
            server_uri = f"{protocol}://{connection_config.host}:{connection_config.port}"

            # Connect using FLEXT LDAP infrastructure
            result = await self._ldap_client.connect(
                server_url=server_uri,
                bind_dn=connection_config.bind_dn,
                password=connection_config.password,
                use_ssl=connection_config.use_ssl,
            )

            # Import ServiceResult dynamically to avoid circular imports
            from flext_core.domain.shared_types import ServiceResult

            if result.success:
                return ServiceResult.ok(result.data)
            return ServiceResult.fail(f"Connection failed: {result.error}")

        except Exception as e:
            from flext_core.domain.shared_types import ServiceResult

            return ServiceResult.fail(f"Connection error: {e}")

    async def disconnect(self, connection_id: str) -> ServiceResult[bool]:
        """Disconnect from directory server.

        Args:
            connection_id: Connection identifier

        Returns:
            ServiceResult indicating success or failure

        """
        try:
            await self._ldap_client.disconnect(connection_id)
            from flext_core.domain.shared_types import ServiceResult

            return ServiceResult.ok(True)
        except Exception as e:
            from flext_core.domain.shared_types import ServiceResult

            return ServiceResult.fail(f"Disconnect error: {e}")

    async def search(
        self,
        connection_id: str,
        base_dn: str,
        search_filter: str,
        attributes: list[str] | None = None,
        scope: str = "sub",
    ) -> ServiceResult[list[DirectoryEntryProtocol]]:
        """Search directory entries using FLEXT LDAP.

        Args:
            connection_id: Connection identifier
            base_dn: Base distinguished name for search
            search_filter: LDAP search filter
            attributes: Attributes to retrieve (None for all)
            scope: Search scope (base, one, sub)

        Returns:
            ServiceResult containing list of entries or error

        """
        try:
            result = await self._ldap_client.search(
                connection_id=connection_id,
                base_dn=base_dn,
                search_filter=search_filter,
                attributes=attributes or ["*"],
                scope=scope,
            )

            from flext_core.domain.shared_types import ServiceResult

            if result.success and result.data:
                # Convert FLEXT LDAP entries to DirectoryEntryProtocol format
                entries = []
                for entry in result.data:
                    # Create a simple object that implements DirectoryEntryProtocol
                    class DirectoryEntry:
                        def __init__(
                            self,
                            dn: str,
                            attributes: dict[str, Any],
                            object_classes: list[str],
                        ) -> None:
                            self.dn = dn
                            self.attributes = attributes
                            self.object_classes = object_classes

                    directory_entry = DirectoryEntry(
                        dn=entry.get("dn", ""),
                        attributes=entry.get("attributes", {}),
                        object_classes=entry.get("attributes", {}).get(
                            "objectClass",
                            [],
                        ),
                    )
                    entries.append(directory_entry)

                return ServiceResult.ok(entries)
            return ServiceResult.fail(f"Search failed: {result.error}")

        except Exception as e:
            from flext_core.domain.shared_types import ServiceResult

            return ServiceResult.fail(f"Search error: {e}")

    async def add_entry(
        self,
        connection_id: str,
        dn: str,
        attributes: dict[str, list[str]],
    ) -> ServiceResult[bool]:
        """Add new directory entry using FLEXT LDAP.

        Args:
            connection_id: Connection identifier
            dn: Distinguished name for new entry
            attributes: Entry attributes

        Returns:
            ServiceResult indicating success or failure

        """
        try:
            result = await self._ldap_client.add_entry(
                connection_id=connection_id,
                dn=dn,
                attributes=attributes,
            )

            from flext_core.domain.shared_types import ServiceResult

            if result.success:
                return ServiceResult.ok(True)
            return ServiceResult.fail(f"Add entry failed: {result.error}")

        except Exception as e:
            from flext_core.domain.shared_types import ServiceResult

            return ServiceResult.fail(f"Add entry error: {e}")

    async def modify_entry(
        self,
        connection_id: str,
        dn: str,
        changes: dict[str, Any],
    ) -> ServiceResult[bool]:
        """Modify existing directory entry using FLEXT LDAP.

        Args:
            connection_id: Connection identifier
            dn: Distinguished name of entry to modify
            changes: Modifications to apply

        Returns:
            ServiceResult indicating success or failure

        """
        try:
            result = await self._ldap_client.modify_entry(
                connection_id=connection_id,
                dn=dn,
                changes=changes,
            )

            from flext_core.domain.shared_types import ServiceResult

            if result.success:
                return ServiceResult.ok(True)
            return ServiceResult.fail(f"Modify entry failed: {result.error}")

        except Exception as e:
            from flext_core.domain.shared_types import ServiceResult

            return ServiceResult.fail(f"Modify entry error: {e}")

    async def delete_entry(
        self,
        connection_id: str,
        dn: str,
    ) -> ServiceResult[bool]:
        """Delete directory entry using FLEXT LDAP.

        Args:
            connection_id: Connection identifier
            dn: Distinguished name of entry to delete

        Returns:
            ServiceResult indicating success or failure

        """
        try:
            result = await self._ldap_client.delete_entry(
                connection_id=connection_id,
                dn=dn,
            )

            from flext_core.domain.shared_types import ServiceResult

            if result.success:
                return ServiceResult.ok(True)
            return ServiceResult.fail(f"Delete entry failed: {result.error}")

        except Exception as e:
            from flext_core.domain.shared_types import ServiceResult

            return ServiceResult.fail(f"Delete entry error: {e}")


class FlextLDAPDirectoryAdapter(DirectoryAdapterInterface):
    """Adapter that provides FLEXT LDAP directory service implementation."""

    def get_directory_service(self) -> DirectoryServiceInterface:
        """Get FLEXT LDAP directory service implementation.

        Returns:
            Configured FLEXT LDAP directory service implementation

        """
        return FlextLDAPDirectoryService()

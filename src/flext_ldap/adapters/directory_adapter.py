"""Directory Service Adapter - Implements flext-core FlextLdapDirectoryServiceInterface.

This adapter bridges the flext-core abstract domain interface with
the concrete FLEXT LDAP infrastructure implementation.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol, cast

from flext_core import FlextResult

from flext_ldap.ldap_infrastructure import FlextLdapClient as FlextLdapSimpleClient


# 🚨 LOCAL PROTOCOLS - Clean Architecture compliance
class FlextLdapDirectoryConnectionProtocol(Protocol):
    """Protocol for directory connections."""

    host: str
    port: int


class FlextLdapDirectoryEntryProtocol(Protocol):
    """Protocol for directory entries."""

    dn: str
    attributes: dict[str, object]


class FlextLdapDirectoryServiceInterface(ABC):
    """Abstract interface for directory operations."""

    @abstractmethod
    async def connect(self) -> FlextResult[bool]:
        """Connect to directory service."""
        ...

    @abstractmethod
    async def search_users(
        self,
        filter_criteria: dict[str, object],
    ) -> FlextResult[list[FlextLdapDirectoryEntryProtocol]]:
        """Search for users."""
        ...


class FlextLdapDirectoryAdapterInterface(ABC):
    """Abstract interface for directory adapters."""

    @abstractmethod
    def get_directory_service(self) -> FlextLdapDirectoryServiceInterface:
        """Get directory service implementation."""
        ...


class FlextLdapDirectoryService(FlextLdapDirectoryServiceInterface):
    """Concrete implementation of FlextLdapDirectoryServiceInterface."""

    _ldap_client: FlextLdapSimpleClient | None = None

    def __init__(self) -> None:
        """Initialize FLEXT LDAP directory service."""
        if self._ldap_client is None:
            self._ldap_client = FlextLdapSimpleClient()

    async def connect(
        self,
        server_url: str,
        *,
        bind_dn: str | None = None,
        password: str | None = None,
        timeout: int | None = None,  # noqa: ASYNC109
        verify_ssl: bool | None = None,
        start_tls: bool | None = None,
        tls_options: dict[str, object] | None = None,
        tls_version: str | None = None,
        tls_ciphers: list[str] | None = None,
        tls_cert_reqs: int | None = None,
        tls_ca_certs: str | None = None,
    ) -> FlextResult[bool]:
        """Establish connection to directory server using FLEXT LDAP.

        Returns:
            FlextResult indicating connection success or error

        """
        try:
            # Use default connection for simplicity
            await self._ldap_client.connect(
                server_url=server_url,
                bind_dn=bind_dn,
                password=password,
                timeout=timeout,
                verify_ssl=verify_ssl,
                start_tls=start_tls,
                tls_options=tls_options,
                tls_version=tls_version,
                tls_ciphers=tls_ciphers,
                tls_cert_reqs=tls_cert_reqs,
                tls_ca_certs=tls_ca_certs,
            )
            return FlextResult.ok(data=True)

        except ConnectionError as e:
            return FlextResult.fail(f"Connection error: {e}")
        except OSError as e:
            return FlextResult.fail(f"Network error: {e}")

    async def search_users(
        self,
        search_filter: str,
        base_dn: str = "",
        scope: str = "sub",
        attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdapDirectoryEntryProtocol]]:
        """Search for users in directory."""
        try:
            result = await self._ldap_client.search(
                connection_id=self._ldap_client.connection_id,
                search_base=base_dn,
                search_filter=search_filter,
                attributes=attributes or ["*"],
                scope=scope,
            )

            if result.is_success and result.data:
                entries = [
                    cast(
                        "FlextLdapDirectoryEntryProtocol",
                        entry,
                    )
                    for entry in result.data
                ]

            return FlextResult.ok(data=entries)

        except ConnectionError as e:
            return FlextResult.fail(f"Search connection error: {e}")
        except ValueError as e:
            return FlextResult.fail(f"Search parameter error: {e}")
        except OSError as e:
            return FlextResult.fail(f"Search network error: {e}")

    async def disconnect(self, connection_id: str) -> FlextResult[bool]:
        """Disconnect from directory server.

        Args:
            connection_id: Connection identifier

        Returns:
            FlextResult indicating success or failure

        """
        try:
            await self._ldap_client.disconnect(connection_id)
            return FlextResult.ok(data=True)
        except ConnectionError as e:
            return FlextResult.fail(f"Disconnect connection error: {e}")
        except OSError as e:
            return FlextResult.fail(f"Disconnect network error: {e}")

    async def search(
        self,
        connection_id: str,
        base_dn: str,
        search_filter: str,
        attributes: list[str] | None = None,
        scope: str = "sub",
    ) -> FlextResult[list[FlextLdapDirectoryEntryProtocol]]:
        """Search directory entries using FLEXT LDAP.

        Args:
            connection_id: Connection identifier
            base_dn: Base distinguished name for search
            search_filter: LDAP search filter
            attributes: Attributes to retrieve (None for all)
            scope: Search scope (base, one, sub)

        Returns:
            FlextResult containing list of entries or error

        """
        try:
            result = await self._ldap_client.search(
                connection_id=connection_id,
                search_base=base_dn,
                search_filter=search_filter,
                attributes=attributes or ["*"],
                scope=scope,
            )

            if result.is_success and result.data:
                # Convert FLEXT LDAP entries to FlextLdapDirectoryEntryProtocol format
                entries = []
                for entry in result.data:
                    # Create a simple object that implements
                    # FlextLdapDirectoryEntryProtocol
                    class DirectoryEntry:
                        def __init__(
                            self,
                            dn: str,
                            attributes: dict[str, object],
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
                    entries.append(
                        cast("FlextLdapDirectoryEntryProtocol", directory_entry),
                    )

                return FlextResult.ok(entries)
            return FlextResult.fail(f"Search failed: {result.error}")

        except ConnectionError as e:
            return FlextResult.fail(f"Search connection error: {e}")
        except ValueError as e:
            return FlextResult.fail(f"Search parameter error: {e}")
        except OSError as e:
            return FlextResult.fail(f"Search network error: {e}")

    async def add_entry(
        self,
        connection_id: str,
        dn: str,
        attributes: dict[str, list[str]],
    ) -> FlextResult[bool]:
        """Add new directory entry using FLEXT LDAP.

        Args:
            connection_id: Connection identifier
            dn: Distinguished name for new entry
            attributes: Entry attributes

        Returns:
            FlextResult indicating success or failure

        """
        try:
            result = await self._ldap_client.add(
                connection_id=connection_id,
                dn=dn,
                object_class=["top"],  # Default object class
                attributes=attributes,
            )

            if result.is_success:
                return FlextResult.ok(data=True)
            return FlextResult.fail(f"Add entry failed: {result.error}")

        except ConnectionError as e:
            return FlextResult.fail(f"Add entry error: {e}")

    async def modify_entry(
        self,
        connection_id: str,
        dn: str,
        changes: dict[str, object],
    ) -> FlextResult[bool]:
        """Modify existing directory entry using FLEXT LDAP.

        Args:
            connection_id: Connection identifier
            dn: Distinguished name of entry to modify
            changes: Modifications to apply

        Returns:
            FlextResult indicating success or failure

        """
        try:
            result = await self._ldap_client.modify(
                connection_id=connection_id,
                dn=dn,
                changes=changes,
            )

            if result.is_success:
                return FlextResult.ok(data=True)
            return FlextResult.fail(f"Modify entry failed: {result.error}")

        except ConnectionError as e:
            return FlextResult.fail(f"Modify entry connection error: {e}")
        except ValueError as e:
            return FlextResult.fail(f"Modify entry parameter error: {e}")
        except OSError as e:
            return FlextResult.fail(f"Modify entry network error: {e}")

    async def delete_entry(
        self,
        connection_id: str,
        dn: str,
    ) -> FlextResult[bool]:
        """Delete directory entry using FLEXT LDAP.

        Args:
            connection_id: Connection identifier
            dn: Distinguished name of entry to delete

        Returns:
            FlextResult indicating success or failure

        """
        try:
            result = await self._ldap_client.delete(
                connection_id=connection_id,
                dn=dn,
            )

            if result.is_success:
                return FlextResult.ok(data=True)
            return FlextResult.fail(f"Delete entry failed: {result.error}")

        except ConnectionError as e:
            return FlextResult.fail(f"Delete entry connection error: {e}")
        except ValueError as e:
            return FlextResult.fail(f"Delete entry parameter error: {e}")
        except OSError as e:
            return FlextResult.fail(f"Delete entry network error: {e}")


class FlextLdapDirectoryAdapter(FlextLdapDirectoryAdapterInterface):
    """Adapter that provides FLEXT LDAP directory service implementation."""

    def get_directory_service(self) -> FlextLdapDirectoryServiceInterface:
        """Get FLEXT LDAP directory service implementation.

        Returns:
            Configured FLEXT LDAP directory service implementation

        """
        return FlextLdapDirectoryService()


# Backward compatibility aliases
DirectoryConnectionProtocol = FlextLdapDirectoryConnectionProtocol
DirectoryEntryProtocol = FlextLdapDirectoryEntryProtocol
DirectoryServiceInterface = FlextLdapDirectoryServiceInterface
DirectoryAdapterInterface = FlextLdapDirectoryAdapterInterface

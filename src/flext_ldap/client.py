"""LDAP Client Adapter - FLEXT Architecture Integration.

This module provides a backward-compatible LDAPClient interface that uses
the new FLEXT infrastructure internally, eliminating code duplication while
maintaining API compatibility for existing code and tests.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, Self

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

# Use standard Python logging
import logging

# Use simplified flext-core imports (following new standards)
from flext_core import (
    ConnectionProtocol,
    DomainError as FlextConnectionError,
    ServiceResult,
)
from ldap3.core.exceptions import LDAPException

from flext_ldap.config import FlextLDAPSettings, LDAPConnectionConfig
from flext_ldap.infrastructure.ldap_client import LDAPInfrastructureClient
from flext_ldap.models import LDAPEntry as LDAPEntryModel, LDAPScope

logger = logging.getLogger(__name__)


class LDAPClient(ConnectionProtocol):
    """Enterprise LDAP client using FLEXT architecture internally.

    This is an adapter that provides backward compatibility with the original
    LDAPClient interface while using the new FLEXT infrastructure internally.
    This eliminates code duplication and unifies the implementation.
    """

    def __init__(
        self,
        config: LDAPConnectionConfig | FlextLDAPSettings | None = None,
    ) -> None:
        """Initialize the LDAP client.

        Args:
            config: The LDAP connection configuration.

        """
        if config is None:
            self.settings: FlextLDAPSettings | None = FlextLDAPSettings()
            self.config = self.settings.connection
        elif isinstance(config, FlextLDAPSettings):
            self.settings = config
            self.config = config.connection
        else:
            self.config = config
            self.settings = None

        # Use new FLEXT infrastructure internally
        self._infrastructure_client = LDAPInfrastructureClient()
        self._connection_id: str | None = None
        self._connected = False

    async def __aenter__(self) -> Self:
        """Enter the context manager."""
        await self.connect()
        if not self._connected:
            msg = "Failed to connect"
            raise LDAPException(msg)
        return self

    async def __aexit__(self, *args: object) -> None:
        """Exit the context manager."""
        await self.disconnect()

    async def connect(self) -> None:
        """Connect to LDAP server using new infrastructure."""
        if self._connected:
            return

        try:
            # Use new infrastructure to connect
            server_url = f"ldap://{self.config.server}:{self.config.port}"
            result = await self._infrastructure_client.connect(
                server_url=server_url,
                bind_dn=getattr(self.config, "bind_dn", None),
                password=getattr(self.config, "password", None),
            )

            if result.success:
                self._connection_id = (
                    result.data
                )  # Connection ID returned by infrastructure
                self._connected = True
            else:
                self._connected = False
                raise FlextConnectionError(result.error or "Connection failed")

        except (FlextConnectionError, ValueError, RuntimeError) as e:
            self._connected = False
            msg = f"Connection error: {e}"
            raise FlextConnectionError(msg) from e

    async def disconnect(self) -> None:
        """Disconnect from LDAP server."""
        if self._connection_id and self._connected:
            await self._infrastructure_client.disconnect(self._connection_id)
            self._connected = False
            self._connection_id = None

    async def ping(self) -> bool:
        """Test connection health."""
        if not self._connected or not self._connection_id:
            return False

        try:
            # Test connection by performing a simple search
            result = await self.search(
                base_dn="",
                search_filter="(objectClass=*)",
                scope=LDAPScope.BASE,
                attributes=[],
            )
            return result.success
        except Exception:
            return False

    async def search(
        self,
        base_dn: str,
        search_filter: str = "(objectClass=*)",
        scope: LDAPScope = LDAPScope.SUBTREE,
        attributes: list[str] | None = None,
    ) -> ServiceResult[Any]:
        """Search LDAP directory using new infrastructure."""
        if not self._connected or not self._connection_id:
            return ServiceResult.fail("Not connected to LDAP server")

        try:
            # Use new infrastructure for search
            result = await self._infrastructure_client.search(
                connection_id=self._connection_id,
                base_dn=base_dn,
                search_filter=search_filter,
                scope=scope.value,
                attributes=attributes or [],
            )

            if result.success and result.data is not None:
                # Convert to legacy LDAPEntryModel format for compatibility
                entries = []
                for entry_data in result.data:
                    entry_model = LDAPEntryModel(
                        dn=entry_data.get("dn", ""),
                        attributes=entry_data.get("attributes", {}),
                    )
                    entries.append(entry_model)
                return ServiceResult.ok(entries)
            return ServiceResult.fail(result.error or "Search failed")

        except (ValueError, KeyError, AttributeError) as e:
            return ServiceResult.fail(f"Search error: {e}")

    async def modify(
        self,
        dn: str,
        changes: dict[str, Any],
    ) -> ServiceResult[Any]:
        """Modify LDAP entry using new infrastructure."""
        if not self._connected or not self._connection_id:
            return ServiceResult.fail("Not connected to LDAP server")

        try:
            # Use new infrastructure for modify
            result = await self._infrastructure_client.modify_entry(
                connection_id=self._connection_id,
                dn=dn,
                changes=changes,
            )

            if result.success:
                return result
            return ServiceResult.fail(result.error or "Modify failed")

        except (ValueError, KeyError, AttributeError) as e:
            return ServiceResult.fail(f"Modify error: {e}")

    def is_connected(self) -> bool:
        """Check if client is connected to LDAP server."""
        return self._connected

    def get_server_info(self) -> dict[str, str | None]:
        """Get server information.

        Returns compatibility with original LDAPClient interface.
        """
        if not self._connected or not self._connection_id:
            return {"status": "disconnected"}

        # Get info from new infrastructure
        result = self._infrastructure_client.get_connection_info(self._connection_id)
        if result.success and result.data is not None:
            # Ensure returned dict has correct type signature
            info_dict = result.data
            return {k: str(v) if v is not None else None for k, v in info_dict.items()}
        return {
            "server": getattr(self.config, "server", None),
            "port": str(getattr(self.config, "port", 389)),
            "connected": str(self._connected).lower(),
            "error": result.error,
        }

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[Self]:
        """Context manager for LDAP transactions."""
        # For now, just yield self - transactions can be implemented later
        # when the infrastructure supports them
        yield self


# Maintain backward compatibility
__all__ = ["LDAPClient"]

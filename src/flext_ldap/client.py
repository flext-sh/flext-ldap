"""LDAP Client Adapter - FLEXT Architecture Integration.

This module provides a backward-compatible LDAPClient interface that uses
the new FLEXT infrastructure internally, eliminating code duplication while
maintaining API compatibility for existing code and tests.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, Self

from flext_core import (
    FlextConnectionError,
    FlextResult,
    get_logger,
)
from ldap3.core.exceptions import LDAPException

from flext_ldap.config import FlextLdapConnectionConfig, FlextLdapSettings
from flext_ldap.infrastructure.ldap_simple_client import (
    FlextLdapSimpleClient,
    LdapConnectionConfig,
)
from flext_ldap.models import LDAPEntry as LDAPEntryModel, LDAPScope

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

# Backward compatibility
FlextLDAPSettings = FlextLdapSettings
LDAPConnectionConfig = FlextLdapConnectionConfig

logger = get_logger(__name__)


class FlextLdapClient:
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
        self._infrastructure_client = FlextLdapSimpleClient()
        self._connection_id: str | None = None
        self._connected = False

    async def __aenter__(self) -> Self:
        """Enter the context manager using FLEXT connection services."""
        try:
            # Convert config to LdapConnectionConfig
            ldap_config = LdapConnectionConfig(
                server_url=f"ldap://{self.config.server}:{self.config.port}",
                bind_dn=self.settings.auth.bind_dn if self.settings else "",
                password=self.settings.auth.bind_password if self.settings else "",
                use_ssl=self.config.use_ssl,
                connection_timeout=self.config.timeout_seconds,
            )

            result = await self._infrastructure_client.connect(ldap_config)
            if result.success:
                self._connection_id = result.data
                self._connected = True
                return self
            msg = result.error or "Failed to create connection context"
            raise FlextConnectionError(msg)
        except LDAPException as exc:
            raise FlextConnectionError(str(exc)) from exc

    async def __aexit__(self, *args: object) -> None:
        """Exit the context manager."""
        await self.disconnect()

    async def connect(self) -> None:
        """Connect to LDAP server using FLEXT connection services."""
        if self._connected:
            return

        try:
            # Convert config to LdapConnectionConfig
            ldap_config = LdapConnectionConfig(
                server_url=f"ldap://{self.config.server}:{self.config.port}",
                bind_dn=self.settings.auth.bind_dn if self.settings else "",
                password=self.settings.auth.bind_password if self.settings else "",
                use_ssl=self.config.use_ssl,
                connection_timeout=self.config.timeout_seconds,
            )

            result = await self._infrastructure_client.connect(ldap_config)

            if result.success:
                self._connection_id = result.data
                self._connected = True
                server_url = f"ldap://{self.config.server}:{self.config.port}"
                logger.info(f"FLEXT LDAP connection established: {server_url}")
            else:
                self._connected = False
                error_msg = result.error or "Connection failed"
                raise FlextConnectionError(
                    error_msg,
                    details={"config": self.config.model_dump()},
                )

        except Exception as e:
            self._connected = False
            logger.exception(f"FLEXT LDAP connection failed: {e}")
            msg = f"Connection error: {e}"
            raise FlextConnectionError(
                msg,
                details={"config": self.config.model_dump()},
            ) from e

    async def disconnect(self) -> None:
        """Disconnect from LDAP server using FLEXT connection services."""
        if self._connection_id and self._connected:
            result = await self._infrastructure_client.disconnect(self._connection_id)
            self._connected = False
            self._connection_id = None
            if not result.success:
                logger.warning(f"FLEXT LDAP disconnect warning: {result.error}")

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
    ) -> FlextResult[Any]:
        """Search LDAP directory using new infrastructure."""
        if not self._connected or not self._connection_id:
            return FlextResult.fail("Not connected to LDAP server")

        try:
            # Use new infrastructure for search
            result = await self._infrastructure_client.search(
                connection_id=self._connection_id,
                search_base=base_dn,
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
                return FlextResult.ok(entries)
            return FlextResult.fail(result.error or "Search failed")

        except (ValueError, KeyError, AttributeError) as e:
            return FlextResult.fail(f"Search error: {e}")

    async def modify(
        self,
        dn: str,
        changes: dict[str, Any],
    ) -> FlextResult[Any]:
        """Modify LDAP entry using new infrastructure."""
        if not self._connected or not self._connection_id:
            return FlextResult.fail("Not connected to LDAP server")

        try:
            # Use new infrastructure for modify
            result = await self._infrastructure_client.modify(
                connection_id=self._connection_id,
                dn=dn,
                changes=changes,
            )

            if result.success:
                return result
            return FlextResult.fail(result.error or "Modify failed")

        except (ValueError, KeyError, AttributeError) as e:
            return FlextResult.fail(f"Modify error: {e}")

    def is_connected(self) -> bool:
        """Check if client is connected to LDAP server."""
        return self._connected

    def get_server_info(self) -> dict[str, str | None]:
        """Get server information.

        Returns compatibility with original LDAPClient interface.
        """
        if not self._connected or not self._connection_id:
            return {"status": "disconnected"}

        # Return basic connection info since detailed info is not available
        return {
            "server": self.config.server,
            "port": str(self.config.port),
            "connected": str(self._connected).lower(),
            "connection_id": self._connection_id,
        }

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[Self]:
        """Context manager for LDAP transactions."""
        # For now, just yield self - transactions can be implemented later
        # when the infrastructure supports them
        yield self


# Maintain backward compatibility
__all__ = ["FlextLdapClient"]

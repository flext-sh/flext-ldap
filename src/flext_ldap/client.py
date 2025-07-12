"""LDAP Client implementation using FLEXT Core patterns.

Copyright (c) 2025 FLEXT
SPDX-License-Identifier: MIT

This module provides an LDAP client implementation using FLEXT Core patterns.
It uses flext-core's ServiceResult for error handling and flext-observability's
logging for logging.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Self

from ldap3 import ALL, Connection, Server
from ldap3.core.exceptions import LDAPException

from flext_core.domain.types import ServiceResult
from flext_ldap.config import FlextLDAPSettings
from flext_ldap.models import LDAPScope
from flext_ldap.operations import ModifyOperation, SearchOperation
from flext_observability.logging import get_logger

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from flext_ldap.config import LDAPConnectionConfig
    from flext_ldap.models import LDAPEntry, LDAPFilter

logger = get_logger(__name__)


class LDAPClient:
    """Enterprise LDAP client using flext-core patterns."""

    def __init__(
        self,
        config: LDAPConnectionConfig | FlextLDAPSettings | None = None,
    ) -> None:
        """Initialize the LDAP client.

        Args:
            config: The LDAP connection configuration.

        """
        if config is None:
            config = FlextLDAPSettings()
        elif isinstance(config, FlextLDAPSettings):
            self.settings = config
            self.config = config.connection
        else:
            self.config = config
            self.settings = None

        self._connection: Connection | None = None
        self._server: Server | None = None

    async def __aenter__(self) -> Self:
        """Enter the context manager.

        Raises:
            LDAPException: If the LDAP connection fails.

        Returns:
            The LDAP client.

        """
        result = await self.connect()
        if not result.is_success:
            logger.error("LDAP connection failed", error=result.error_message)
            raise LDAPException(result.error_message or "Connection failed")
        return self

    async def __aexit__(self, *_: object) -> None:
        """Exit the context manager.

        Args:
            *_: The exception context.

        """
        await self.disconnect()

    async def connect(self) -> ServiceResult[None]:
        """Connect to the LDAP server.

        Returns:
            The result of the connection.

        """
        try:
            logger.info(
                "Connecting to LDAP server",
                server=self.config.server,
                port=self.config.port,
            )

            self._server = Server(
                self.config.server,
                port=self.config.port,
                use_ssl=self.config.use_tls or self.config.use_ssl,
                get_info=ALL,
            )

            # Get password from settings if available:
            password = None
            if self.settings and self.settings.auth.bind_password:
                password = self.settings.auth.bind_password.get_secret_value()
            elif hasattr(self.config, "bind_password") and self.config.bind_password:
                password = self.config.bind_password.get_secret_value()

            bind_dn = None
            if self.settings:
                bind_dn = self.settings.auth.bind_dn
            elif hasattr(self.config, "bind_dn"):
                bind_dn = self.config.bind_dn

            self._connection = Connection(
                self._server,
                user=bind_dn,
                password=password,
                auto_bind=True,
            )

            logger.info("LDAP connection established", server=self.config.server)
            return ServiceResult.success(None)

        except LDAPException as e:
            logger.exception(
                "LDAP connection failed",
                error=str(e),
                server=self.config.server,
            )
            return ServiceResult.failure(f"LDAP connection failed: {e}")
        except Exception as e:
            logger.exception("Unexpected error during LDAP connection", error=str(e))
            return ServiceResult.failure(f"Unexpected error: {e}")

    async def disconnect(self) -> None:
        """Disconnect from the LDAP server."""
        if self._connection:
            logger.info("Disconnecting from LDAP server")
            self._connection.unbind()
            self._connection = None
            self._server = None

    async def search(
        self,
        base_dn: str | None = None,
        filter_obj: LDAPFilter | str = "(object_class=*)",
        scope: LDAPScope | str = LDAPScope.SUBTREE,
        attributes: list[str] | None = None,
    ) -> ServiceResult[list[LDAPEntry]]:
        """Search for LDAP entries.

        Args:
            base_dn: The base DN to search from.
            filter_obj: The filter to use for the search.
            scope: The scope of the search.
            attributes: The attributes to return.

        Returns:
            The result of the search.

        """
        if not self._connection:
            return ServiceResult.failure("Not connected to LDAP server")

        # Use configured base_dn if not provided:
        if base_dn is None:
            base_dn = self.settings.search.base_dn if self.settings else ""

        try:
            search_op = SearchOperation(self._connection)
            result = await search_op.execute(
                base_dn=base_dn,
                filter_obj=filter_obj,
                scope=scope if isinstance(scope, LDAPScope) else LDAPScope.SUBTREE,
                attributes=attributes,
            )

            if result.is_success:
                logger.info(
                    "LDAP search completed",
                    base_dn=base_dn,
                    filter=str(filter_obj),
                    results_count=len(result.value),
                )
                return ServiceResult.success(result.value)
            logger.error(
                "LDAP search failed",
                base_dn=base_dn,
                filter=str(filter_obj),
                error=result.error,
            )
            return ServiceResult.failure(result.error or "Search failed")

        except Exception as e:
            logger.exception(
                "Unexpected error during LDAP search",
                base_dn=base_dn,
                filter=str(filter_obj),
                error=str(e),
            )
            return ServiceResult.failure(f"Search error: {e}")

    async def modify(
        self,
        dn: str,
        changes: dict[str, list[tuple[str, list[str]]]],
    ) -> ServiceResult[None]:
        """Modify an LDAP entry.

        Args:
            dn: The DN of the entry to modify.
            changes: The changes to make to the entry.

        Returns:
            The result of the modification.

        """
        if not self._connection:
            return ServiceResult.failure("Not connected to LDAP server")

        try:
            modify_op = ModifyOperation(self._connection)
            result = await modify_op.execute(dn, changes)

            if result.is_success:
                logger.info("LDAP modify completed", dn=dn)
                return ServiceResult.success(None)
            logger.error("LDAP modify failed", dn=dn, error=result.error)
            return ServiceResult.failure(result.error or "Modify failed")

        except Exception as e:
            logger.exception("Unexpected error during LDAP modify", dn=dn, error=str(e))
            return ServiceResult.failure(f"Modify error: {e}")

    def is_connected(self) -> bool:
        """Check if the LDAP client is connected.

        Returns:
            True if the LDAP client is connected, False otherwise.

        """
        return bool(self._connection and self._connection.bound)

    def get_server_info(self) -> dict[str, str | None]:
        """Get the server information.

        Returns:
            The server information.

        """
        if not self._server:
            return {"status": "disconnected"}

        return {
            "server": str(self._server.host),
            "port": str(self._server.port),
            "ssl": str(self._server.ssl),
            "status": "connected" if self.is_connected() else "disconnected",
        }

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[Self]:
        """Context manager for LDAP transactions.

        Yields:
            The LDAP client.

        Raises:
            LDAPException: If the LDAP connection fails.

        """
        if not self.is_connected():
            result = await self.connect()
            if not result.is_success:
                raise LDAPException(result.error_message or "Connection failed")

        try:
            yield self
        finally:
            # LDAP doesn't have transactions, but we can ensure cleanup:
            pass


__all__ = [
    "LDAPClient",
]

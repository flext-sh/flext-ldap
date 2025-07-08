# Copyright (c) 2025 FLEXT
# SPDX-License-Identifier: MIT

"""LDAP Client implementation using FLEXT Core patterns."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, Self

from ldap3 import ALL, Connection, Server
from ldap3.core.exceptions import LDAPException
from pydantic import BaseModel, SecretStr

from flext_ldap.models import LDAPEntry, LDAPFilter, LDAPScope
from flext_ldap.operations import ModifyOperation, SearchOperation
from flext_ldap.result import Result

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


class LDAPConfig(BaseModel):
    """LDAP configuration with strict validation."""

    server: str = "localhost"
    port: int = 389
    use_tls: bool = False
    bind_dn: str | None = None
    bind_password: SecretStr | None = None
    base_dn: str = ""
    timeout: int = 30


class LDAPClient:
    """Enterprise LDAP client with minimal, clean implementation."""

    def __init__(self, config: LDAPConfig) -> None:
        """Initialize LDAP client with configuration."""
        self.config = config
        self._connection: Connection | None = None
        self._server: Server | None = None

    async def __aenter__(self) -> Self:
        """Async context manager entry.

        Returns:
            Self: The connected LDAP client instance.

        Raises:
            LDAPException: If connection fails.

        """
        result = await self.connect()
        if not result.is_success:
            msg = f"Connection failed: {result.error}"
            raise LDAPException(msg)
        return self

    async def __aexit__(self, *_: object) -> None:
        """Async context manager exit."""
        await self.disconnect()

    async def connect(self) -> Result[None]:
        """Establish LDAP connection.

        Returns:
            Result[None]: Success result if connected, failure otherwise.

        """
        try:
            self._server = Server(
                self.config.server,
                port=self.config.port,
                use_ssl=self.config.use_tls,
                get_info=ALL,
            )

            password = (
                self.config.bind_password.get_secret_value()
                if self.config.bind_password
                else None
            )

            self._connection = Connection(
                self._server,
                user=self.config.bind_dn,
                password=password,
                auto_bind=True,
            )

            return Result.success(None)
        except LDAPException as e:
            return Result.failure(str(e))

    async def disconnect(self) -> None:
        """Close LDAP connection."""
        if self._connection:
            self._connection.unbind()  # type: ignore[no-untyped-call]
            self._connection = None

    async def search(
        self,
        base_dn: str | None = None,
        filter_obj: LDAPFilter | str = "(objectClass=*)",
        scope: LDAPScope = LDAPScope.SUBTREE,
        attributes: list[str] | None = None,
    ) -> Result[list[LDAPEntry]]:
        """Execute LDAP search operation.

        Returns:
            Result[list[LDAPEntry]]: List of found entries on success.

        """
        if not self._connection:
            return Result.failure("Not connected to LDAP server")

        search_op = SearchOperation(self._connection)
        return await search_op.execute(
            base_dn or self.config.base_dn,
            filter_obj,
            scope,
            attributes,
        )

    async def modify(
        self,
        dn: str,
        changes: dict[str, list[tuple[str, Any]]],
    ) -> Result[None]:
        """Execute LDAP modify operation.

        Returns:
            Result[None]: Success result if modified, failure otherwise.

        """
        if not self._connection:
            return Result.failure("Not connected to LDAP server")

        modify_op = ModifyOperation(self._connection)
        return await modify_op.execute(dn, changes)

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[LDAPClient]:
        """LDAP transaction context (simplified).

        Yields:
            LDAPClient: The client instance for transaction operations.

        Raises:
            LDAPException: If transaction fails.

        """
        try:
            yield self
        except Exception as e:
            # In a real implementation, this would rollback changes
            msg = f"Transaction failed: {e}"
            raise LDAPException(msg) from e

"""FLEXT LDAP CLI - Single class using flext-cli exclusively.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import asyncio

from flext_core import FlextLogger, FlextResult, FlextTypes
from flext_core.typings import FlextTypes

from flext_ldap.api import FlextLDAPApi

logger = FlextLogger(__name__)


class FlextLDAPCli:
    """Single FLEXT LDAP CLI class using flext-cli exclusively."""

    def __init__(self) -> None:
        """Initialize unified LDAP CLI using flext-cli exclusively."""
        self._api = FlextLDAPApi()
        # FlextCliApi integration deferred
        self._cli = None

    def test_connection(
        self,
        server: str,
        bind_dn: str,
        bind_password: str,
    ) -> FlextResult[FlextTypes.Core.Dict]:
        """Test LDAP connection.

        Args:
            server: The server to connect to.
            bind_dn: The bind DN to use.
            bind_password: The bind password to use.

        Returns:
            FlextResult[FlextTypes.Core.Dict]: Connection test result.

        """

        async def _test() -> FlextResult[FlextTypes.Core.Dict]:
            try:
                connection_result = await self._api.connect(
                    server,
                    bind_dn,
                    bind_password,
                )
                if not connection_result.is_success:
                    return FlextResult.fail(
                        f"Connection failed: {connection_result.error}",
                    )

                await self._api.disconnect(connection_result.value)
                return FlextResult.ok(
                    {"status": "connected", "server": server, "bind_dn": bind_dn},
                )
            except Exception as e:
                logger.exception("LDAP connection test failed")
                return FlextResult.fail(f"Connection error: {e}")

        return asyncio.run(_test())

    def run_command(self, command: str, **kwargs: object) -> None:
        """Execute CLI command using flext-cli patterns."""
        if command == "test":
            result = self.test_connection(
                str(kwargs["server"]),
                str(kwargs["bind_dn"]),
                str(kwargs["bind_password"]),
            )

            if result.is_success:
                logger.info("Connection test successful")
            else:
                logger.error("Connection test failed: %s", result.error)


__all__ = [
    "FlextLDAPCli",
]

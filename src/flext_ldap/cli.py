"""FLEXT LDAP CLI - Single class using flext-cli exclusively."""

from __future__ import annotations

import asyncio

from flext_cli import FlextCliApi
from flext_core import FlextLogger, FlextResult

from flext_ldap.api import FlextLDAPApi

logger = FlextLogger(__name__)


class FlextLDAPCli:
    """Single FLEXT LDAP CLI class using flext-cli exclusively."""

    def __init__(self) -> None:
        """Initialize unified LDAP CLI using flext-cli exclusively."""
        self._api = FlextLDAPApi()
        self._cli = FlextCliApi()

    def test_connection(
        self, server: str, bind_dn: str, bind_password: str
    ) -> FlextResult[dict[str, object]]:
        """Test LDAP connection."""

        async def _test() -> FlextResult[dict[str, object]]:
            try:
                connection_result = await self._api.connect(
                    server, bind_dn, bind_password
                )
                if not connection_result.is_success:
                    return FlextResult.fail(
                        f"Connection failed: {connection_result.error}"
                    )

                await self._api.disconnect(connection_result.value)
                return FlextResult.ok(
                    {"status": "connected", "server": server, "bind_dn": bind_dn}
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
                logger.error(f"Connection test failed: {result.error}")


__all__ = [
    "FlextLDAPCli",
]

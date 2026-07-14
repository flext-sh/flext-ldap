"""Runtime mixin used by the public LDAP API facade."""

from __future__ import annotations

import types
from typing import Self


class FlextLdapApiRuntime:
    """Context manager behavior composed by the public LDAP facade."""

    def __enter__(self) -> Self:
        """Context manager entry."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        """Context manager exit with automatic disconnection."""
        self.disconnect()

    def disconnect(self) -> None:
        """Disconnect contract provided by composed connection service."""
        msg = "disconnect() must be provided by composed LDAP connection service"
        raise NotImplementedError(msg)


__all__: list[str] = ["FlextLdapApiRuntime"]

"""Runtime mixin used by the public LDAP API facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Self

if TYPE_CHECKING:
    import types


class FlextLdapApiRuntime:
    """Context manager behavior composed by the public LDAP facade."""

    def __enter__(self) -> Self:
        """Context manager entry.

        Returns:
            The resulting ``Self`` value.

        """
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

"""Public API facade for flext-ldap.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import types
from typing import ClassVar, Self, override

from pydantic import ConfigDict

from flext_ldap import (
    FlextLdapConnection,
    FlextLdapOperations,
    FlextLdapSettings,
    FlextLdapSync,
    c,
    m,
    p,
    r,
)


class FlextLdap(FlextLdapSync, FlextLdapOperations, FlextLdapConnection):
    """Public LDAP facade composed through cooperative MRO."""

    _instance: ClassVar[Self | None] = None
    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=False,
        extra="forbid",
        arbitrary_types_allowed=True,
    )

    @classmethod
    def get_instance(cls) -> Self:
        """Return the shared LDAP facade instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    @override
    def _get_service_config_type(cls) -> type[FlextLdapSettings]:
        """Get the service-specific configuration type."""
        return FlextLdapSettings

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

    @override
    def execute(
        self, **_kwargs: str | float | bool | None
    ) -> p.Result[m.Ldap.SearchResult]:
        """Execute service health check."""
        if not self.is_connected:
            return r[m.Ldap.SearchResult].fail(str(c.Ldap.ErrorStrings.NOT_CONNECTED))
        return r[m.Ldap.SearchResult].ok(
            m.Ldap.SearchResult(entries=[], search_options=None),
        )


ldap = FlextLdap.get_instance()


__all__: list[str] = ["FlextLdap", "ldap"]

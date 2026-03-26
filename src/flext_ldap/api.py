"""Public API facade for flext-ldap.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import types
from typing import ClassVar, Self, override

from flext_core import r
from pydantic import ConfigDict

from flext_ldap import (
    FlextLdapConnection,
    FlextLdapOperations,
    FlextLdapSettings,
    FlextLdapSync,
    c,
    m,
)


class FlextLdap(FlextLdapSync, FlextLdapOperations, FlextLdapConnection):
    """Public LDAP facade composed through cooperative MRO."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=False,
        extra="ignore",
        arbitrary_types_allowed=True,
    )

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
    def execute(self, **_kwargs: object) -> r[m.Ldap.SearchResult]:
        """Execute service health check."""
        if not self.is_connected:
            return r[m.Ldap.SearchResult].fail(str(c.Ldap.ErrorStrings.NOT_CONNECTED))
        return r[m.Ldap.SearchResult].ok(
            m.Ldap.SearchResult(entries=[], search_options=None),
        )


ldap = FlextLdap

__all__ = ["FlextLdap", "ldap"]

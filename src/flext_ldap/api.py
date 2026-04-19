"""Public API facade for flext-ldap.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import types
from typing import Self

from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.sync import FlextLdapSync


class FlextLdap(FlextLdapSync, FlextLdapConnection):
    """Public LDAP facade composed through cooperative MRO."""

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


ldap = FlextLdap()


__all__: list[str] = ["FlextLdap", "ldap"]

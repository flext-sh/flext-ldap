"""LDAP structural duck-typing protocol contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from flext_ldap import t


class FlextLdapProtocolsStructural:
    """LDAP structural duck-typing protocol contracts composed into ``p.Ldap``."""

    @runtime_checkable
    class HasItemsMethod(Protocol):
        """Protocol for objects with items() method."""

        @staticmethod
        def items() -> Sequence[tuple[str, t.JsonValue]]:
            """Return items as sequence of tuples."""
            ...

    @runtime_checkable
    class HasConfigAttribute(Protocol):
        """Protocol for objects exposing configuration (settings duck typing)."""

        @property
        def settings(self) -> t.JsonValue:
            """The resolved configuration t.JsonValue."""
            ...

    @runtime_checkable
    class HasDynamicAttribute(Protocol):
        """Protocol for objects with dynamic attribute access via getattr."""

        def __getattr__(self, name: str) -> None:
            """Get dynamic attribute."""
            ...

    @runtime_checkable
    class HasAttributesProperty(Protocol):
        """Protocol for objects with 'attributes' property.

        Uses Mapping (covariant) instead of dict (invariant) to allow structural
        compatibility with dict subtypes and Sequence subtypes in values.
        """

        @property
        def attributes(self) -> Mapping[str, t.Ldap.Ldap3EntryValue]:
            """The attributes property - covariant Mapping.

            Structurally compatible.
            """
            ...


__all__: list[str] = ["FlextLdapProtocolsStructural"]

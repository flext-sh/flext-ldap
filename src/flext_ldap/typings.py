# AUTO-GENERATED FILE — Regenerate with: make gen
"""FLEXT LDAP type definitions with strict direct contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from flext_ldif import t

from flext_ldap._typings import FlextLdapTypesLdap


class FlextLdapTypes(t):
    """LDAP-specific type namespace."""

    class Ldap(FlextLdapTypesLdap):
        """LDAP type aliases."""


t = FlextLdapTypes
__all__: list[str] = ["FlextLdapTypes", "t"]

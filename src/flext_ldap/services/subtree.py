"""Extracted facade class for subtree.

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

from flext_ldap.services._subtree import FlextLdapServicesSubtreeDelete


class FlextLdapServicesSubtree(
    FlextLdapServicesSubtreeDelete,
):
    """Facade for subtree."""


__all__: list[str] = ["FlextLdapServicesSubtree"]

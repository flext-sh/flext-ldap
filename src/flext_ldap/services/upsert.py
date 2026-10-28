"""Extracted facade class for upsert.

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

from flext_ldap.services._upsert import FlextLdapServicesUpsertHandler


class FlextLdapServicesUpsert(
    FlextLdapServicesUpsertHandler,
):
    """Facade for upsert."""


__all__: list[str] = ["FlextLdapServicesUpsert"]

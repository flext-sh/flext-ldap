"""LDAP validation utility methods.

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

from typing import TypeIs

from flext_ldap import c, t
from flext_ldap._utilities import FlextLdapUtilitiesBase


class FlextLdapUtilitiesValidation(FlextLdapUtilitiesBase):
    """LDAP validation helpers."""

    @staticmethod
    def valid_status(value: str | t.JsonValue) -> TypeIs[str]:
        """Return whether a value is a valid LDAP status.

        Args:
            value: Candidate value to validate.

        Returns:
            True when the value is a known LDAP status string.

        """
        if isinstance(value, c.Ldap.Status):
            return True
        return value in c.Ldap.VALID_STATUSES


__all__: list[str] = ["FlextLdapUtilitiesValidation"]

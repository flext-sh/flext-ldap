"""LDAP validation utility methods."""

from __future__ import annotations

from typing import TypeIs

from flext_ldap import c, t


class FlextLdapUtilitiesValidation:
    """LDAP validation helpers."""

    @staticmethod
    def is_valid_status(value: str | t.JsonValue) -> TypeIs[str]:
        """Return whether a value is a valid LDAP status."""
        if isinstance(value, c.Ldap.Status):
            return True
        return value in c.Ldap.VALID_STATUSES


__all__: list[str] = ["FlextLdapUtilitiesValidation"]

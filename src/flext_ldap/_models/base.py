"""Base models for flext-ldap.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import m


class FlextLdapModelsBase:
    """Base models for flext-ldap."""

    class ConfigNamespace(m.BaseModel):
        """Open, frozen namespace for YAML-owned LDAP business rules."""

        model_config = m.ConfigDict(extra="allow", frozen=True)


__all__: tuple[str, ...] = ("FlextLdapModelsBase",)

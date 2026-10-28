"""Layer-zero schemas for YAML-owned LDAP configuration.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldap/config_models
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class FlextLdapModelsConfigNamespace:
    """Configuration declarations independent of the model facade."""

    class ConfigNamespace(BaseModel):
        """Open, frozen namespace for YAML-owned LDAP business rules."""

        model_config = ConfigDict(extra="allow", frozen=True)


__all__: tuple[str, ...] = ("FlextLdapModelsConfigNamespace",)

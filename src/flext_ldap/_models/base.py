"""Base models for flext-ldap.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap.config_models import FlextLdapConfigNamespaceModels


class FlextLdapModelsBase(FlextLdapConfigNamespaceModels):
    """Base models for flext-ldap."""


__all__: tuple[str, ...] = ("FlextLdapModelsBase",)

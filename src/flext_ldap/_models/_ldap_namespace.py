"""Ldap namespace module.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldap/_models/_ldap_namespace
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap import m


class _LdapNamespace(m.BaseModel):
    """Open, frozen namespace exposing every ``config/*.yaml`` domain model-less."""

    model_config = m.ConfigDict(extra="allow", frozen=True)

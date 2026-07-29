"""FlextLdapConfig — frozen config singleton for flext-ldap (ADR-005 §7).

Model-less: business rules live in ``config/*.yaml`` under the ``Ldap:`` key and
are exposed through the open ``config.Ldap`` namespace (``extra="allow"``), with
no per-domain model. Access is ``config.Ldap.<domain>[<key>...]``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from flext_cli import FlextCliConfig


class _LdapNamespace(BaseModel):
    """Open, frozen namespace exposing every ``config/*.yaml`` domain model-less."""

    model_config = ConfigDict(extra="allow", frozen=True)


class FlextLdapConfig(FlextCliConfig):
    """Ldap config auto-loaded model-less from ``config/*.yaml``."""

    Ldap: _LdapNamespace = _LdapNamespace()


config: FlextLdapConfig = FlextLdapConfig.fetch_global()
"""Pre-instantiated frozen config singleton — ``from flext_ldap import config``."""

__all__: list[str] = ["FlextLdapConfig", "config"]

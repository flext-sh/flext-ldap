"""FlextLdapConfig — frozen config singleton for flext-ldap (ADR-005 §7).

Model-less: business rules live in ``config/*.yaml`` under the ``Ldap:`` key and
are exposed through the open ``config.Ldap`` namespace (``extra="allow"``), with
no per-domain model. Access is ``config.Ldap.<domain>[<key>...]``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Annotated

from flext_core import FlextConfig
from flext_core import m
from flext_ldap._models._ldap_namespace import FlextLdapModelsLdapNamespace


class FlextLdapConfig(FlextConfig):
    """Ldap config auto-loaded model-less from ``config/*.yaml``."""

    Ldap: Annotated[
        FlextLdapModelsLdapNamespace,
        m.Field(
            description="Open namespace exposing ``config/*.yaml`` under ``Ldap``.",
        ),
    ] = FlextLdapModelsLdapNamespace()


config: FlextLdapConfig = FlextLdapConfig.fetch_global()
"""Pre-instantiated frozen config singleton — ``from flext_ldap import config``."""

__all__: list[str] = ["FlextLdapConfig", "config"]

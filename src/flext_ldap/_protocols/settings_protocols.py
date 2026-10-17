"""Namespaced LDAP settings protocol contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from flext_ldif import FlextLdifProtocols


class FlextLdapProtocolsSettings:
    """LDAP settings protocol contracts composed into ``p.Ldap``."""

    @runtime_checkable
    class LdapSettings(FlextLdifProtocols.Model, Protocol):
        """Namespaced LDAP runtime settings branch."""

        host: str
        port: int
        use_ssl: bool
        use_tls: bool
        bind_dn: str
        bind_password: str
        timeout: int
        auto_bind: bool
        auto_range: bool

    @runtime_checkable
    class Settings(FlextLdifProtocols.Ldif.Settings, Protocol):
        """MRO-composed settings contract with the LDAP namespace."""

        @property
        def ldap(self) -> FlextLdapProtocolsSettings.LdapSettings:
            """Namespaced LDAP settings branch (read-only for covariance)."""
            ...


__all__: list[str] = ["FlextLdapProtocolsSettings"]

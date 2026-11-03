# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldap/_protocols/config
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_ldif import FlextLdifProtocols

if TYPE_CHECKING:
    from flext_ldap._protocols import FlextLdapProtocolsConfig


class FlextLdapProtocolsConfig:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class Identity(FlextLdifProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def name(self) -> str:
            """LDAP project name."""
            ...

    @runtime_checkable
    class Connection(FlextLdifProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def port(self) -> int:
            """Default LDAP server port."""
            ...

        @property
        def timeout_seconds(self) -> int:
            """Default LDAP operation timeout in seconds."""
            ...

        @property
        def max_retries(self) -> int:
            """Maximum connection retry attempts."""
            ...

        @property
        def retry_delay_seconds(self) -> float:
            """Delay between retry attempts in seconds."""
            ...

        @property
        def auto_bind(self) -> bool:
            """Auto-bind connection after connect."""
            ...

        @property
        def auto_range(self) -> bool:
            """Enable LDAP range retrieval."""
            ...

        @property
        def default_batch_size(self) -> int:
            """Default LDAP search batch size."""
            ...

    @runtime_checkable
    class Validation(FlextLdifProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def vendor_string_max_tokens(self) -> int:
            """Maximum tokens in a vendor string."""
            ...

        @property
        def dn_truncation_length(self) -> int:
            """Maximum displayed length of a DN."""
            ...

        @property
        def multi_phase_param_count(self) -> int:
            """Parameter count for multi-phase operations."""
            ...

        @property
        def single_phase_param_count(self) -> int:
            """Parameter count for single-phase operations."""
            ...

        @property
        def example_base_dn(self) -> str:
            """Example base DN used in fixtures and docs."""
            ...

    @runtime_checkable
    class Ldap(FlextLdifProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def identity(self) -> FlextLdapProtocolsConfig.Identity:
            """LDAP identity metadata."""
            ...

        @property
        def connection(self) -> FlextLdapProtocolsConfig.Connection:
            """LDAP connection defaults and thresholds."""
            ...

        @property
        def validation(self) -> FlextLdapProtocolsConfig.Validation:
            """LDAP validation and example defaults."""
            ...

    @runtime_checkable
    class Root(FlextLdifProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        Ldap: FlextLdapProtocolsConfig.Ldap


__all__: list[str] = [
    "FlextLdapProtocolsConfig",
]

"""LDAP Protocol Definitions - Protocol Interfaces for FLEXT LDAP Operations.

Protocols use structural typing only - no model imports.
This allows protocols to remain independent of model implementations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from flext_ldif import FlextLdifProtocols

from flext_ldap._protocols import (
    client_protocols as _client_protocols,
    search_protocols as _search_protocols,
    service_protocols as _service_protocols,
    settings_protocols as _settings_protocols,
    structural_protocols as _structural_protocols,
)


class FlextLdapProtocols(FlextLdifProtocols):
    """LDAP-specific protocol definitions.

    Domain-specific protocol interfaces for LDAP operations.
    All protocols are nested within this class following the single-class pattern.
    Uses structural typing only - no model imports.

    **Namespace Structure:**
    All LDAP-specific protocols are organized under the `.Ldap` namespace
    at ROOT level to enable proper namespace separation and alignment with
    flext-ldif and flext-cli patterns.

    HIERARCHY:
    ──────────
    Layer 0: Domain Protocols (no internal dependencies)
    Layer 1: Service Protocols (can use Layer 0)
    Layer 2: Handler Protocols (can use Layer 0 and 1)
    """

    @runtime_checkable
    class Ldap(Protocol):
        """LDAP-specific protocol namespace.

        All LDAP domain-specific protocols are organized here at ROOT level
        to enable proper namespace separation. LDIF protocols from parent
        are accessed via `.Ldif` namespace (e.g., `m.Ldif.Entry`).

        Pattern: `FlextLdapProtocols.Ldap.ProtocolName` (aligned with flext-ldif,
        flext-cli)
        """

        LdapSettings = _settings_protocols.LdapSettings
        Settings = _settings_protocols.Settings

        # ── Layer 0: Domain Protocols ────────────────────────────
        # DN, Attributes, Entry → use _ldif_p.Ldif.DN,
        # _ldif_p.Ldif.Attributes, _ldif_p.Ldif.Entry
        # directly from flext-ldif (SSOT — no redefinition in Ldap namespace)

        LdapBatchStats = _search_protocols.LdapBatchStats
        ConnectionConfig = _search_protocols.ConnectionConfig
        SearchScope = _search_protocols.SearchScope
        SearchOptions = _search_protocols.SearchOptions
        OperationResult = _search_protocols.OperationResult
        SearchResult = _search_protocols.SearchResult
        PhaseSyncResult = _search_protocols.PhaseSyncResult

        # ── Layer 1: Service Protocols ───────────────────────────

        LdapClient = _client_protocols.LdapClient
        LdapAdapter = _client_protocols.LdapAdapter
        LdapConnection = _service_protocols.LdapConnection
        LdapOperations = _service_protocols.LdapOperations

        # ── LDAP runtime object contracts ────────────────────────
        # The base structural ldap3 contracts live in flext-ldif (``p.Ldif``)
        # as the single source of truth and are reached through MRO; this
        # package extends only what it needs.

        Ldap3Connection = _service_protocols.Ldap3Connection

        # ── Structural Duck-Typing Protocols ─────────────────────

        HasItemsMethod = _structural_protocols.HasItemsMethod
        HasConfigAttribute = _structural_protocols.HasConfigAttribute
        HasDynamicAttribute = _structural_protocols.HasDynamicAttribute
        HasAttributesProperty = _structural_protocols.HasAttributesProperty


p = FlextLdapProtocols

__all__: list[str] = ["FlextLdapProtocols", "p"]

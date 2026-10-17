# AUTO-GENERATED FILE — Regenerate with: make gen
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
    FlextLdapProtocolsClient,
    FlextLdapProtocolsSearch,
    FlextLdapProtocolsService,
    FlextLdapProtocolsSettings,
    FlextLdapProtocolsStructural,
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

        LdapSettings = FlextLdapProtocolsSettings.LdapSettings
        Settings = FlextLdapProtocolsSettings.Settings

        # ── Layer 0: Domain Protocols ────────────────────────────
        # DN, Attributes, Entry → use _ldif_p.Ldif.DN,
        # _ldif_p.Ldif.Attributes, _ldif_p.Ldif.Entry
        # directly from flext-ldif (SSOT — no redefinition in Ldap namespace)

        LdapBatchStats = FlextLdapProtocolsSearch.LdapBatchStats
        ConnectionConfig = FlextLdapProtocolsSearch.ConnectionConfig
        SearchScope = FlextLdapProtocolsSearch.SearchScope
        SearchOptions = FlextLdapProtocolsSearch.SearchOptions
        OperationResult = FlextLdapProtocolsSearch.OperationResult
        SearchResult = FlextLdapProtocolsSearch.SearchResult
        PhaseSyncResult = FlextLdapProtocolsSearch.PhaseSyncResult

        # ── Layer 1: Service Protocols ───────────────────────────

        LdapClient = FlextLdapProtocolsClient.LdapClient
        LdapAdapter = FlextLdapProtocolsClient.LdapAdapter
        LdapConnection = FlextLdapProtocolsService.LdapConnection
        LdapOperations = FlextLdapProtocolsService.LdapOperations

        # ── LDAP runtime object contracts ────────────────────────
        # The base structural ldap3 contracts live in flext-ldif (``p.Ldif``)
        # as the single source of truth and are reached through MRO; this
        # package extends only what it needs.

        Ldap3Connection = FlextLdapProtocolsService.Ldap3Connection

        # ── Structural Duck-Typing Protocols ─────────────────────

        HasItemsMethod = FlextLdapProtocolsStructural.HasItemsMethod
        HasConfigAttribute = FlextLdapProtocolsStructural.HasConfigAttribute
        HasDynamicAttribute = FlextLdapProtocolsStructural.HasDynamicAttribute
        HasAttributesProperty = FlextLdapProtocolsStructural.HasAttributesProperty


p = FlextLdapProtocols

__all__: list[str] = ["FlextLdapProtocols", "p"]

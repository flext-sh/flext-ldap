# AUTO-GENERATED FILE — Regenerate with: make gen
"""LDAP Protocol Definitions - Protocol Interfaces for FLEXT LDAP Operations.

Protocols use structural typing only - no model imports.
This allows protocols to remain independent of model implementations.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

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

    class Ldap(
        FlextLdapProtocolsClient,
        FlextLdapProtocolsSearch,
        FlextLdapProtocolsService,
        FlextLdapProtocolsSettings,
        FlextLdapProtocolsStructural,
    ):
        """LDAP-specific protocol namespace.

        All LDAP domain-specific protocols are organized here at ROOT level
        to enable proper namespace separation. LDIF protocols from parent
        are accessed via `.Ldif` namespace (e.g., `m.Ldif.Entry`).

        Pattern: `FlextLdapProtocols.Ldap.ProtocolName` (aligned with flext-ldif,
        flext-cli)
        """


p = FlextLdapProtocols

__all__: list[str] = ["FlextLdapProtocols", "p"]

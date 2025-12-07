"""Protocol definitions for flext-ldap tests.

Provides TestsLdapProtocols, extending FlextTestsProtocols with flext-ldap-specific
protocols. All generic test protocols come from flext_tests.

Architecture:
- FlextTestsProtocols (flext_tests) = Generic protocols for all FLEXT projects
- TestsLdapProtocols (tests/) = flext-ldap-specific protocols extending FlextTestsProtocols

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests.protocols import FlextTestsProtocols

from flext_ldap.protocols import FlextLdapProtocols


class TestsFlextLdapProtocols(FlextTestsProtocols, FlextLdapProtocols):
    """Protocol definitions for flext-ldap tests - extends FlextTestsProtocols and FlextLdapProtocols.

    Architecture: Extends both FlextTestsProtocols and FlextLdapProtocols with flext-ldap-specific protocol definitions.
    All generic protocols from FlextTestsProtocols and production protocols from FlextLdapProtocols are available through inheritance.

    Rules:
    - NEVER redeclare protocols from FlextTestsProtocols or FlextLdapProtocols
    - Only flext-ldap-specific protocols allowed (not generic for other projects)
    - All generic protocols come from FlextTestsProtocols
    - All production protocols come from FlextLdapProtocols
    """

    # Test-specific protocols can be added here as nested classes
    # Example:
    # @runtime_checkable
    # class TestClientProtocol(Protocol):
    #     """Test-specific client protocol."""
    #     pass


# Runtime alias for simplified usage
p = TestsFlextLdapProtocols

__all__ = [
    "TestsFlextLdapProtocols",
    "p",
]

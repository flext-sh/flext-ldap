"""LDAP protocol definitions for flext-ldap domain.

This module contains all protocol interfaces and abstract base classes
used throughout the flext-ldap domain. Following FLEXT standards, all
protocols are organized under a single FlextLdapProtocols class.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC

from flext_core import FlextHandlers, FlextProtocols, FlextResult


class FlextLdapProtocols(FlextProtocols):
    """Unified LDAP protocols class extending FlextProtocols with LDAP-specific protocols.

    This class extends the base FlextProtocols with LDAP-specific protocol definitions,
    abstract base classes, and interface specifications following FLEXT domain separation patterns.
    """

    class Repository(FlextHandlers[object, FlextResult[object]], ABC):
        """Base repository protocol for LDAP operations."""

    class Connection(FlextHandlers[object, FlextResult[object]], ABC):
        """Base connection protocol for LDAP operations."""

    class Authentication(FlextHandlers[object, FlextResult[object]], ABC):
        """Base authentication protocol for LDAP operations."""

    class Search(FlextHandlers[object, FlextResult[object]], ABC):
        """Base search protocol for LDAP operations."""

    class Validation(FlextHandlers[object, FlextResult[object]], ABC):
        """Base validation protocol for LDAP operations."""

    class Configuration(FlextHandlers[object, FlextResult[object]], ABC):
        """Base configuration protocol for LDAP operations."""


__all__ = [
    "FlextLdapProtocols",
]

"""LDAP server operations and capabilities management.

Provides server-specific operations, capability detection, and configuration
management for various LDAP server types (OpenLDAP, Oracle OID/OUD, AD, etc.).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_core import FlextResult, FlextService


class FlextLdapServersService(FlextService[None]):
    """LDAP server operations and capabilities management.

    Provides:
    - Server type detection and configuration
    - Server-specific capabilities
    - Default port management
    - STARTTLS support detection
    - Server-specific attribute handling
    """

    # Server type constants
    SERVER_OPENLDAP1: ClassVar[str] = "openldap1"
    SERVER_OPENLDAP2: ClassVar[str] = "openldap2"
    SERVER_OID: ClassVar[str] = "oid"
    SERVER_OUD: ClassVar[str] = "oud"
    SERVER_AD: ClassVar[str] = "ad"
    SERVER_GENERIC: ClassVar[str] = "generic"

    def __init__(self, server_type: str | None = None) -> None:
        """Initialize server operations with server type.

        Args:
            server_type: LDAP server type (openldap1, openldap2, oid, oud, ad, generic).

        """
        super().__init__()
        self._server_type = server_type or self.SERVER_GENERIC

    def execute(self) -> FlextResult[None]:
        """Execute server operations."""
        return FlextResult[None].ok(None)

    def get_default_port(self, *, use_ssl: bool = False) -> int:
        """Get default port for server type.

        Args:
            use_ssl: If True, return SSL port; otherwise standard port.

        Returns:
            Default port number for this server type.

        """
        if use_ssl:
            return 636
        return 389

    @property
    def server_type(self) -> str:
        """Get current server type.

        Returns:
            The configured server type string.

        """
        return self._server_type

    def supports_start_tls(self) -> bool:
        """Check if server supports STARTTLS.

        Returns:
            True if server supports STARTTLS, False otherwise.

        """
        return self._server_type in {
            self.SERVER_OPENLDAP1,
            self.SERVER_OPENLDAP2,
            self.SERVER_GENERIC,
        }

    def is_openldap(self) -> bool:
        """Check if server is OpenLDAP variant.

        Returns:
            True if OpenLDAP 1.x or 2.x, False otherwise.

        """
        return self._server_type in {self.SERVER_OPENLDAP1, self.SERVER_OPENLDAP2}

    def is_oracle(self) -> bool:
        """Check if server is Oracle LDAP (OID or OUD).

        Returns:
            True if OID or OUD, False otherwise.

        """
        return self._server_type in {self.SERVER_OID, self.SERVER_OUD}

    def is_active_directory(self) -> bool:
        """Check if server is Microsoft Active Directory.

        Returns:
            True if AD, False otherwise.

        """
        return self._server_type == self.SERVER_AD

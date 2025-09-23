"""LDAP protocol definitions for flext-ldap domain.

This module contains all protocol interfaces and abstract base classes
used throughout the flext-ldap domain. Following FLEXT standards, all
protocols are organized under a single FlextLdapProtocols class.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from flext_core import FlextResult

if TYPE_CHECKING:
    from flext_ldap.typings import FlextLdapTypes


class FlextLdapProtocols:
    """Unified LDAP protocols class containing all protocol interfaces.

    This class consolidates all LDAP-related protocol definitions, abstract
    base classes, and interface specifications in a single location following
    FLEXT domain separation patterns.
    """

    class Repository(ABC):
        """Base repository protocol for LDAP operations."""

        @abstractmethod
        async def search(
            self,
            base_dn: str,
            filter_str: str,
            attributes: list[str] | None = None,
        ) -> FlextResult[list[dict[str, object]]]:
            """Search for entries in the LDAP directory."""

        @abstractmethod
        async def get(self, dn: str) -> FlextResult[dict[str, object] | None]:
            """Get a single entry by Distinguished Name."""

        @abstractmethod
        async def create(
            self,
            dn: str,
            attributes: FlextLdapTypes.Entry.AttributeDict,
        ) -> FlextResult[bool]:
            """Create a new entry in the LDAP directory."""

        @abstractmethod
        async def update(
            self,
            dn: str,
            attributes: FlextLdapTypes.Entry.AttributeDict,
        ) -> FlextResult[bool]:
            """Update an existing entry in the LDAP directory."""

        @abstractmethod
        async def delete(self, dn: str) -> FlextResult[bool]:
            """Delete an entry from the LDAP directory."""

        @abstractmethod
        async def exists(self, dn: str) -> FlextResult[bool]:
            """Check if an entry exists in the LDAP directory."""

    class Connection(ABC):
        """LDAP connection protocol interface."""

        @abstractmethod
        async def connect(self) -> FlextResult[bool]:
            """Establish connection to the LDAP server."""

        @abstractmethod
        async def disconnect(self) -> FlextResult[bool]:
            """Close connection to the LDAP server."""

        @abstractmethod
        async def is_connected(self) -> bool:
            """Check if currently connected to the LDAP server."""

        @abstractmethod
        async def bind(
            self,
            dn: str | None = None,
            password: str | None = None,
        ) -> FlextResult[bool]:
            """Bind to the LDAP server with credentials."""

        @abstractmethod
        async def unbind(self) -> FlextResult[bool]:
            """Unbind from the LDAP server."""

    class Authentication(ABC):
        """LDAP authentication protocol interface."""

        @abstractmethod
        async def authenticate_user(
            self,
            username: str,
            password: str,
        ) -> FlextResult[bool]:
            """Authenticate a user against the LDAP directory."""

        @abstractmethod
        async def validate_credentials(
            self,
            dn: str,
            password: str,
        ) -> FlextResult[bool]:
            """Validate credentials for a specific DN."""

    class Search(ABC):
        """LDAP search operations protocol interface."""

        @abstractmethod
        async def search_users(
            self,
            filter_str: str | None = None,
            base_dn: str | None = None,
        ) -> FlextResult[list[dict[str, object]]]:
            """Search for user entries."""

        @abstractmethod
        async def search_groups(
            self,
            filter_str: str | None = None,
            base_dn: str | None = None,
        ) -> FlextResult[list[dict[str, object]]]:
            """Search for group entries."""

        @abstractmethod
        async def search_entries(
            self,
            base_dn: str,
            filter_str: str,
            scope: str = "subtree",
            attributes: list[str] | None = None,
        ) -> FlextResult[list[dict[str, object]]]:
            """Generic search for LDAP entries."""

    class Validation(ABC):
        """LDAP validation protocol interface."""

        @abstractmethod
        def validate_dn(self, dn: str) -> FlextResult[str]:
            """Validate Distinguished Name format."""

        @abstractmethod
        def validate_filter(self, filter_str: str) -> FlextResult[str]:
            """Validate LDAP search filter format."""

        @abstractmethod
        def validate_email(self, email: str | None) -> FlextResult[str | None]:
            """Validate email address format."""

        @abstractmethod
        def validate_password(self, password: str | None) -> FlextResult[str | None]:
            """Validate password requirements."""

    class Configuration(ABC):
        """LDAP configuration protocol interface."""

        @abstractmethod
        def get_server_uri(self) -> str:
            """Get the LDAP server URI."""

        @abstractmethod
        def get_bind_dn(self) -> str | None:
            """Get the bind Distinguished Name."""

        @abstractmethod
        def get_base_dn(self) -> str:
            """Get the base Distinguished Name for searches."""

        @abstractmethod
        def get_connection_timeout(self) -> int:
            """Get the connection timeout in seconds."""

        @abstractmethod
        def is_ssl_enabled(self) -> bool:
            """Check if SSL/TLS is enabled."""


__all__ = [
    "FlextLdapProtocols",
]

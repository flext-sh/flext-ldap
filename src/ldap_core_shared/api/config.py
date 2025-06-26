"""LDAP Configuration Module - Value Object Pattern.

This module contains the LDAPConfig Value Object extracted from the monolithic api.py.
It delegates to existing configuration subsystems while providing a clean interface.

DESIGN PATTERN: VALUE OBJECT + DELEGATION
- Immutable configuration data
- Auto-detection capabilities
- Integration with existing config modules
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class LDAPConfig:
    """LDAP Configuration Value Object.

    DESIGN PATTERN: VALUE OBJECT
    ===========================

    This class represents immutable configuration data for LDAP connections.
    It follows the Value Object pattern - contains no business logic, only
    data validation and auto-configuration convenience methods.

    RESPONSIBILITIES:
    - Store LDAP connection parameters
    - Auto-detect configuration from server URLs
    - Provide sensible defaults for common scenarios
    - Validate configuration values during construction

    USAGE PATTERNS:
    - Minimal configuration (server + auth):
        >>> config = LDAPConfig(
        ...     server="ldaps://ldap.company.com",
        ...     auth_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=company,dc=com",
        ...     auth_password="secret",
        ...     base_dn="dc=company,dc=com"
        ... )

    - Auto-detection from URL:
        >>> config = LDAPConfig(
        ...     server="ldaps://ldap.company.com:636",  # Auto-detects TLS + port
        ...     auth_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=company,dc=com",
        ...     auth_password="secret",
        ...     base_dn="dc=company,dc=com"
        ... )

    - Enterprise configuration:
        >>> config = LDAPConfig(
        ...     server="ldap://primary.company.com",
        ...     auth_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=company,dc=com",
        ...     auth_password="secret",
        ...     base_dn="dc=company,dc=com",
        ...     pool_size=20,
        ...     timeout=60,
        ...     verify_certs=True
        ... )

    INTEGRATION:
    This Value Object is automatically converted to specialized configuration
    objects when passed to enterprise components (ConnectionManager, etc.)
    """

    # Required connection parameters
    server: str  # Server URL or hostname
    auth_dn: str  # Authentication DN
    auth_password: str  # Authentication password
    base_dn: str  # Base DN for operations

    # Optional connection settings (with auto-detection)
    port: int | None = None  # Port (auto-detected from server URL)
    use_tls: bool = True  # Use TLS encryption (auto-detected)
    verify_certs: bool = True  # Verify certificates in TLS mode
    timeout: int = 30  # Connection timeout in seconds
    pool_size: int = 5  # Connection pool size for enterprise mode

    def __post_init__(self) -> None:
        """Auto-configure settings from server URL.

        CONVENIENCE FEATURE: Automatically detects TLS usage and port numbers
        from server URLs, reducing configuration boilerplate for users.

        Auto-detection rules:
        - ldaps:// URLs → use_tls=True, port=636 (if not specified)
        - ldap:// URLs → use_tls=False, port=389 (if not specified)
        - Plain hostnames → use current use_tls setting, default ports

        Example transformations:
        - "ldaps://server.com:636" → server="server.com", use_tls=True, port=636
        - "ldap://server.com" → server="server.com", use_tls=False, port=389
        - "server.com" → server="server.com", use_tls=True (default), port=389/636
        """
        if "://" in self.server:
            # Parse URL for auto-configuration
            if self.server.startswith("ldaps://"):
                self.use_tls = True
                self.port = self.port or 636
            elif self.server.startswith("ldap://"):
                self.use_tls = False
                self.port = self.port or 389

            # Extract hostname from URL
            self.server = self.server.split("://")[1].split(":")[0]
        # Plain hostname - only set port if not already specified
        elif self.port is None:
            self.port = 636 if self.use_tls else 389

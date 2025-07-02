"""LDAP Connection Security Management."""

from __future__ import annotations

import logging

from flext_ldap.connections.base import LDAPConnectionInfo
from flext_ldap.connections.interfaces import (
    BaseConnectionComponent,
)

logger = logging.getLogger(__name__)


class StandardSecurityManager(BaseConnectionComponent):
    """🔥 Single Responsibility: Manage security concerns only.

    SOLID Compliance:
    - S: Only handles security, nothing else
    - O: Extensible through inheritance
    - L: Interchangeable with other security managers
    - I: Implements focused ISecurityManager
    - D: Depends on LDAPConnectionInfo abstraction
    """

    def __init__(self, connection_info: LDAPConnectionInfo) -> None:
        """Initialize security manager.

        Args:
            connection_info: Connection configuration

        """
        super().__init__(connection_info)

    async def initialize(self) -> None:
        """Initialize security manager."""
        await self.validate_credentials(self.connection_info)
        logger.debug("StandardSecurityManager initialized")

    async def cleanup(self) -> None:
        """Cleanup security manager."""
        logger.debug("StandardSecurityManager cleaned up")

    async def validate_credentials(self, connection_info: LDAPConnectionInfo) -> bool:
        """🔥 Validate LDAP credentials and configuration.

        Args:
            connection_info: Connection configuration to validate

        Returns:
            True if credentials are valid, False otherwise

        """
        logger.debug("Validating LDAP credentials")

        # Validate required fields
        if not connection_info.host:
            logger.warning("Missing LDAP host")
            return False

        if not connection_info.bind_dn:
            logger.warning("Missing bind DN")
            return False

        if not connection_info.bind_password.get_secret_value():
            logger.warning("Missing bind password")
            return False

        logger.debug("Credentials validation passed")
        return True

    def validate_dn(self, dn: str) -> bool:
        """🔥 Validate Distinguished Name format.

        Args:
            dn: Distinguished Name to validate

        Returns:
            True if DN is valid, False otherwise

        """
        if not dn or not isinstance(dn, str):
            return False

        # Basic DN validation - must contain at least one component
        if "=" not in dn:
            return False

        # Check for common DN patterns
        dn_components = dn.split(",")
        for raw_component in dn_components:
            component = raw_component.strip()
            if "=" not in component:
                return False

            key, value = component.split("=", 1)
            if not key.strip() or not value.strip():
                return False

        return True

    def sanitize_filter(self, ldap_filter: str) -> str:
        """🔥 Sanitize LDAP filter to prevent injection attacks.

        Args:
            ldap_filter: LDAP filter to sanitize

        Returns:
            Sanitized LDAP filter

        """
        if not ldap_filter:
            return "(objectClass=*)"

        # Escape special characters that could be used for injection
        escape_chars = {
            "*": r"\2a",
            "(": r"\28",
            ")": r"\29",
            "\\": r"\5c",
            "\x00": r"\00",
        }

        # Only escape if the filter doesn't look like a proper LDAP filter
        if not (ldap_filter.startswith("(") and ldap_filter.endswith(")")):
            for char, escape in escape_chars.items():
                ldap_filter = ldap_filter.replace(char, escape)

            # Wrap in parentheses if not already
            ldap_filter = f"({ldap_filter})"

        return ldap_filter

    def validate_attributes(self, attributes: list[str] | None) -> list[str] | None:
        """🔥 Validate and sanitize attribute list.

        Args:
            attributes: List of attributes to validate

        Returns:
            Validated attribute list or None

        """
        if not attributes:
            return None

        validated_attrs = []
        for attr in attributes:
            if isinstance(attr, str) and attr.strip():
                # Remove potentially dangerous characters
                clean_attr = "".join(c for c in attr if c.isalnum() or c in "-_")
                if clean_attr:
                    validated_attrs.append(clean_attr)

        return validated_attrs or None

    def get_security_status(self) -> dict[str, bool]:
        """🔥 Get security validation status.

        Returns:
            Security status dictionary

        """
        return {
            "ssl_enabled": self.connection_info.use_ssl,
            "credentials_valid": bool(
                self.connection_info.bind_dn
                and self.connection_info.bind_password.get_secret_value(),
            ),
            "host_configured": bool(self.connection_info.host),
            "port_configured": bool(self.connection_info.port),
        }

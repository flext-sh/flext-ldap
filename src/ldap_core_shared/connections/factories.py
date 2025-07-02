"""LDAP Connection Factory Implementations."""

from __future__ import annotations

import logging
import ssl
from typing import TYPE_CHECKING

import ldap3

from ldap_core_shared.connections.interfaces import (
    BaseConnectionComponent,
    ISecurityManager,
)

if TYPE_CHECKING:
    from ldap_core_shared.connections.base import LDAPConnectionInfo

logger = logging.getLogger(__name__)


class StandardConnectionFactory(BaseConnectionComponent):
    """🎯 Single Responsibility: Create LDAP connections only.

    SOLID Compliance:
    - S: Only creates connections, nothing else
    - O: Extensible through inheritance
    - L: Interchangeable with other factories
    - I: Implements focused IConnectionFactory
    - D: Depends on LDAPConnectionInfo abstraction
    """

    def __init__(
        self,
        connection_info: LDAPConnectionInfo,
        security_manager: ISecurityManager | None = None,
    ) -> None:
        """Initialize factory with dependencies.

        Args:
            connection_info: Connection configuration
            security_manager: Optional security manager for TLS

        """
        super().__init__(connection_info)
        from ldap_core_shared.connections.security import StandardSecurityManager

        self._security_manager = security_manager or StandardSecurityManager(
            connection_info,
        )

    async def initialize(self) -> None:
        """Initialize factory component."""
        await self._security_manager.validate_credentials(self.connection_info)
        logger.info("🔥 SOLID StandardConnectionFactory initialized")

    async def cleanup(self) -> None:
        """Cleanup factory resources."""
        logger.debug("StandardConnectionFactory cleaned up")

    def create_connection(
        self,
        connection_info: LDAPConnectionInfo,
    ) -> ldap3.Connection:
        """🔥 ZERO DUPLICATION: Create LDAP connection using factory pattern.

        Args:
            connection_info: Connection configuration

        Returns:
            Configured LDAP connection

        """
        # Create TLS configuration
        tls_config = None
        if connection_info.use_ssl:
            tls_config = ldap3.Tls(validate=ssl.CERT_REQUIRED)

        # Create server
        server = ldap3.Server(
            host=connection_info.host,
            port=connection_info.port,
            use_ssl=connection_info.use_ssl,
            tls=tls_config,
            get_info=ldap3.ALL,
        )

        # Create connection
        return ldap3.Connection(
            server=server,
            user=connection_info.bind_dn,
            password=connection_info.bind_password.get_secret_value(),
            authentication=connection_info.get_ldap3_authentication(),
            auto_bind=connection_info.auto_bind,
            lazy=False,
        )

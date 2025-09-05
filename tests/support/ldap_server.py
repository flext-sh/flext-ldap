"""LDAP test server management."""

import asyncio

import docker
import ldap3
from flext_core import FlextLogger, FlextResult

from flext_ldap import FlextLDAPConnectionConfig
from tests.support.test_data import TEST_GROUPS, TEST_OUS, TEST_USERS

logger = FlextLogger(__name__)


class LdapTestServer:
    """Manages Docker-based LDAP test server."""

    def __init__(
        self,
        container_name: str = "flext-ldap-test-server",
        port: int = 3390,
        REDACTED_LDAP_BIND_PASSWORD_password: str = "REDACTED_LDAP_BIND_PASSWORD123",
    ) -> None:
        """Initialize LDAP test server."""
        self.container_name = container_name
        self.port = port
        self.REDACTED_LDAP_BIND_PASSWORD_password = REDACTED_LDAP_BIND_PASSWORD_password
        self.docker_client = docker.from_env()
        self._container: docker.models.containers.Container | None = None

    async def start(self) -> FlextResult[bool]:
        """Start LDAP server container."""
        try:
            # Stop and remove existing container if it exists
            await self.stop()

            # Start new container
            logger.info(f"Starting LDAP test server on port {self.port}")

            self._container = self.docker_client.containers.run(
                image="osixia/openldap:1.5.0",
                name=self.container_name,
                ports={"389/tcp": self.port, "636/tcp": self.port + 1},
                environment={
                    "LDAP_ORGANISATION": "Flext Test",
                    "LDAP_DOMAIN": "internal.invalid",
                    "LDAP_ADMIN_PASSWORD": self.REDACTED_LDAP_BIND_PASSWORD_password,
                    "LDAP_CONFIG_PASSWORD": self.REDACTED_LDAP_BIND_PASSWORD_password,
                    "LDAP_READONLY_USER": "false",
                    "LDAP_RFC2307BIS_SCHEMA": "false",
                    "LDAP_BACKEND": "mdb",
                    "LDAP_TLS": "true",
                    "LDAP_TLS_CRT_FILENAME": "ldap.crt",
                    "LDAP_TLS_KEY_FILENAME": "ldap.key",
                    "LDAP_TLS_DH_PARAM_FILENAME": "dhparam.pem",
                    "LDAP_TLS_CA_CRT_FILENAME": "ca.crt",
                    "LDAP_TLS_ENFORCE": "false",
                    "LDAP_TLS_CIPHER_SUITE": "SECURE256:+SECURE128:-VERS-TLS-ALL:+VERS-TLS1.2:-RSA:-DHE-DSS:-CAMELLIA-128-CBC:-CAMELLIA-256-CBC",
                    "LDAP_TLS_VERIFY_CLIENT": "demand",
                    "LDAP_REPLICATION": "false",
                    "KEEP_EXISTING_CONFIG": "false",
                    "LDAP_REMOVE_CONFIG_AFTER_SETUP": "true",
                    "LDAP_SSL_HELPER_PREFIX": "ldap",
                },
                detach=True,
                remove=False,
                auto_remove=False,
            )

            # Wait for server to be ready
            if await self.wait_for_ready():
                logger.info("LDAP test server started successfully")
                return FlextResult.ok(data=True)
            return FlextResult.error("LDAP server failed to start within timeout")

        except Exception as e:
            logger.exception("Failed to start LDAP server")
            return FlextResult.error(f"Failed to start LDAP server: {e}")

    async def stop(self) -> FlextResult[bool]:
        """Stop and remove LDAP server container."""
        try:
            # Try to find existing container
            try:
                container = self.docker_client.containers.get(self.container_name)
                logger.info(f"Stopping existing container: {self.container_name}")
                container.stop()
                container.remove()
                logger.info("Existing container stopped and removed")
            except docker.errors.NotFound:
                logger.debug("No existing container found")

            self._container = None
            return FlextResult.ok(data=True)

        except Exception as e:
            logger.exception("Failed to stop LDAP server")
            return FlextResult.error(f"Failed to stop LDAP server: {e}")

    async def wait_for_ready(self, timeout_seconds: int = 60) -> bool:
        """Wait for LDAP server to be ready."""
        # ldap3 already imported at top

        try:
            async with asyncio.timeout(timeout_seconds):
                while True:
                    try:
                        # Try to connect to LDAP server
                        server = ldap3.Server(
                            host="localhost",
                            port=self.port,
                            use_ssl=False,
                            connect_timeout=5,
                        )

                        conn = ldap3.Connection(
                            server=server,
                            user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
                            password=self.REDACTED_LDAP_BIND_PASSWORD_password,
                            auto_bind=True,
                            authentication=ldap3.SIMPLE,
                        )

                        # Simple search to verify server is ready
                        conn.search(
                            search_base="dc=flext,dc=local",
                            search_filter="(objectClass=*)",
                            search_scope=ldap3.BASE,
                        )

                        conn.unbind()
                        logger.info("LDAP server is ready")
                        return True

                    except Exception as e:
                        logger.debug(f"LDAP server not ready yet: {e}")
                        await asyncio.sleep(2)

        except TimeoutError:
            logger.exception("LDAP server failed to become ready within timeout")
            return False

    async def setup_test_data(self) -> FlextResult[bool]:
        """Setup initial test data in LDAP server."""
        try:
            # ldap3 and test_data already imported at top

            # Connect to LDAP server
            server = ldap3.Server(
                host="localhost",
                port=self.port,
                use_ssl=False,
            )

            conn = ldap3.Connection(
                server=server,
                user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
                password=self.REDACTED_LDAP_BIND_PASSWORD_password,
                auto_bind=True,
                authentication=ldap3.SIMPLE,
            )

            # Create organizational units first
            for ou_data in TEST_OUS:
                try:
                    conn.add(ou_data["dn"], attributes=ou_data["attributes"])
                    logger.debug(f"Created OU: {ou_data['dn']}")
                except Exception as e:
                    logger.debug(f"Failed to create OU {ou_data['dn']}: {e}")

            # Create test users
            for user_data in TEST_USERS:
                try:
                    conn.add(user_data["dn"], attributes=user_data["attributes"])
                    logger.debug(f"Created user: {user_data['dn']}")
                except Exception as e:
                    logger.debug(f"Failed to create user {user_data['dn']}: {e}")

            # Create test groups
            for group_data in TEST_GROUPS:
                try:
                    conn.add(group_data["dn"], attributes=group_data["attributes"])
                    logger.debug(f"Created group: {group_data['dn']}")
                except Exception as e:
                    logger.debug(f"Failed to create group {group_data['dn']}: {e}")

            conn.unbind()
            logger.info("Test data setup completed")
            return FlextResult.ok(data=True)

        except Exception as e:
            logger.exception("Failed to setup test data")
            return FlextResult.error(f"Failed to setup test data: {e}")

    def get_connection_config(self) -> FlextLDAPConnectionConfig:
        """Get connection configuration for test server."""
        return FlextLDAPConnectionConfig(
            server=f"ldap://localhost:{self.port}",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            bind_password=self.REDACTED_LDAP_BIND_PASSWORD_password,
            base_dn="dc=flext,dc=local",
            use_ssl=False,
            timeout=30,
        )


def get_test_ldap_config() -> FlextLDAPConnectionConfig:
    """Get test LDAP connection configuration."""
    return FlextLDAPConnectionConfig(
        server="ldap://localhost:3390",
        bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
        bind_password="REDACTED_LDAP_BIND_PASSWORD123",
        base_dn="dc=flext,dc=local",
        use_ssl=False,
        timeout=30,
    )


async def wait_for_ldap_server(
    host: str = "localhost",
    port: int = 3390,
    timeout_seconds: int = 60,
) -> bool:
    """Wait for LDAP server to be available."""
    # ldap3 already imported at top

    try:
        async with asyncio.timeout(timeout_seconds):
            while True:
                try:
                    server = ldap3.Server(
                        host=host,
                        port=port,
                        use_ssl=False,
                        connect_timeout=5,
                    )

                    conn = ldap3.Connection(
                        server=server,
                        user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
                        password="REDACTED_LDAP_BIND_PASSWORD123",
                        auto_bind=True,
                        authentication=ldap3.SIMPLE,
                    )

                    conn.search(
                        search_base="dc=flext,dc=local",
                        search_filter="(objectClass=*)",
                        search_scope=ldap3.BASE,
                    )

                    conn.unbind()
                    return True

                except Exception:
                    await asyncio.sleep(2)

    except TimeoutError:
        return False

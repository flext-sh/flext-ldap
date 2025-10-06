"""LDAP test server management using unified FlextTestDocker.

ARCHITECTURAL PRINCIPLE: All Docker operations use FlextTestDocker exclusively
to eliminate direct docker module usage and provide consistent Docker management.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Note: This file has type checking disabled due to limitations in the official types-ldap3 package:
- Method return types (add, delete, search, modify, unbind) are not specified in the stubs
- Properties like conn.entries and entry.entry_dn are not fully typed
- Entry attributes and their values have incomplete type information
"""

# pyright: reportUnknownMemberType=false, reportUnknownVariableType=false, reportUnknownArgumentType=false, reportGeneralTypeIssues=false
import os
from typing import Protocol, TypedDict, cast

from flext_ldap import FlextLDAPModels, FlextLDAPTypes
from flext_ldap.constants import FlextLDAPConstants
from flext_tests import FlextTestDocker

from flext_core import FlextLogger, FlextResult, FlextTypes

from .test_data import TEST_GROUPS, TEST_OUS, TEST_USERS


class ContainerInfo(TypedDict):
    """Container information from Docker."""

    name: str
    status: object  # Status enum, but we'll access .value
    ports: str
    image: str


class DockerManagerProtocol(Protocol):
    """Protocol for Docker manager with required methods."""

    def start_container(self, container_name: str) -> FlextResult[bool]: ...
    def stop_container(
        self, container_name: str, remove: bool
    ) -> FlextResult[bool]: ...
    def get_container_logs(
        self, container_name: str, tail: int
    ) -> FlextResult[str]: ...
    def execute_container_command(
        self, container_name: str, command: str
    ) -> FlextResult[str]: ...
    def get_container_status(
        self, container_name: str
    ) -> FlextResult[ContainerInfo]: ...
    def get_docker_version(self) -> FlextResult[str]: ...


logger = FlextLogger(__name__)


class LdapTestServer:
    """Manages LDAP test server using unified FlextTestDocker."""

    def __init__(
        self,
        container_name: str = "flext-openldap-test",
        port: int = 3390,
        admin_password: str | None = None,
    ) -> None:
        """Initialize LDAP test server with FlextTestDocker management."""
        self.container_name = container_name
        self.port = port
        self.admin_password = admin_password or os.getenv(
            "LDAP_TEST_ADMIN_PASSWORD",
            "admin123",
        )
        # Use unified FlextTestDocker instead of direct docker client
        self.docker_manager: DockerManagerProtocol = cast(
            "DockerManagerProtocol", FlextTestDocker()
        )
        self._container: object | None = None  # For backward compatibility

    def start(self) -> FlextResult[bool]:
        """Start LDAP server container using FlextTestDocker."""
        try:
            logger.info(
                "Starting LDAP test server on port %s using FlextTestDocker", self.port
            )

            # Use FlextTestDocker to start the shared OpenLDAP container
            start_result = self.docker_manager.start_container(self.container_name)
            if start_result.is_failure:
                return FlextResult[bool].fail(
                    f"Failed to start LDAP container: {start_result.error}"
                )

            # Wait for server to be ready
            if self.wait_for_ready():
                logger.info("LDAP test server started successfully via FlextTestDocker")
                return FlextResult[bool].ok(data=True)
            return FlextResult[bool].fail("LDAP server failed to start within timeout")

        except Exception as e:
            logger.exception("Failed to start LDAP server")
            return FlextResult[bool].fail(f"Failed to start LDAP server: {e}")

    def stop(self) -> FlextResult[bool]:
        """Stop LDAP server container using FlextTestDocker."""
        try:
            logger.info("Stopping LDAP container: %s", self.container_name)

            # Use FlextTestDocker to stop the container
            stop_result = self.docker_manager.stop_container(
                self.container_name, remove=False
            )
            if stop_result.is_failure:
                logger.warning("Container stop reported failure: %s", stop_result.error)
                # Don't fail here as the container might already be stopped

            logger.info("LDAP container stop requested via FlextTestDocker")
            return FlextResult[bool].ok(data=True)

        except Exception as e:
            logger.exception("Failed to stop LDAP server")
            return FlextResult[bool].fail(f"Failed to stop LDAP server: {e}")

    def wait_for_ready(self, timeout_seconds: int = 60) -> bool:
        """Wait for LDAP server to be ready."""
        import time

        start_time = time.time()
        while time.time() - start_time < timeout_seconds:
            try:
                # Try to connect to LDAP server
                server = FlextLDAPTypes.Server(
                    host="localhost",
                    port=self.port,
                    use_ssl=False,
                    connect_timeout=5,
                )

                conn = FlextLDAPTypes.Connection(
                    server=server,
                    user="cn=admin,dc=flext,dc=local",
                    password=self.admin_password,
                    auto_bind=True,
                    authentication=FlextLDAPTypes.SIMPLE,
                )

                conn.search(
                    search_base="dc=flext,dc=local",
                    search_filter="(objectClass=*)",
                    search_scope=FlextLDAPTypes.BASE,
                )

                conn.unbind()
                logger.info("LDAP server is ready")
                return True
            except Exception as e:
                logger.debug("LDAP server not ready yet: %s", e)
                time.sleep(FlextLDAPConstants.LdapRetry.SERVER_READY_RETRY_DELAY)

        logger.exception("LDAP server failed to become ready within timeout")
        return False

    def setup_test_data(self) -> FlextResult[bool]:
        """Set up initial test data in LDAP server."""
        try:
            # Connect to LDAP server
            server = FlextLDAPTypes.Server(
                host="localhost",
                port=self.port,
                use_ssl=False,
            )

            conn = FlextLDAPTypes.Connection(
                server=server,
                user="cn=admin,dc=flext,dc=local",
                password=self.admin_password,
                auto_bind=True,
                authentication=FlextLDAPTypes.SIMPLE,
            )

            # Create organizational units first
            for ou_data in TEST_OUS:
                try:
                    conn.add(
                        cast("str", ou_data["dn"]),
                        attributes=cast("FlextTypes.Dict", ou_data["attributes"]),
                    )
                    logger.debug("Created OU: %s", ou_data["dn"])
                except Exception as e:
                    logger.debug("Failed to create OU %s: %s", ou_data["dn"], e)

            # Create test users
            for user_data in TEST_USERS:
                try:
                    conn.add(
                        cast("str", user_data["dn"]),
                        attributes=cast("FlextTypes.Dict", user_data["attributes"]),
                    )
                    logger.debug("Created user: %s", user_data["dn"])
                except Exception as e:
                    logger.debug("Failed to create user %s: %s", user_data["dn"], e)

            # Create test groups
            for group_data in TEST_GROUPS:
                try:
                    conn.add(
                        cast("str", group_data["dn"]),
                        attributes=cast("FlextTypes.Dict", group_data["attributes"]),
                    )
                    logger.debug("Created group: %s", group_data["dn"])
                except Exception as e:
                    logger.debug("Failed to create group %s: %s", group_data["dn"], e)

            conn.unbind()
            logger.info("Test data setup completed")
            return FlextResult[bool].ok(data=True)

        except Exception as e:
            logger.exception("Failed to setup test data")
            return FlextResult[bool].fail(f"Failed to setup test data: {e}")

    def get_connection_config(self) -> FlextLDAPModels.ConnectionConfig:
        """Get connection configuration for test server."""
        return FlextLDAPModels.ConnectionConfig(
            server=f"ldap://localhost:{self.port}",
            bind_dn="cn=admin,dc=flext,dc=local",
            bind_password=self.admin_password or "admin123",
            use_ssl=False,
            timeout=30,
        )

    def get_container_logs(self, tail: int = 100) -> FlextResult[str]:
        """Get container logs using FlextTestDocker."""
        return self.docker_manager.get_container_logs(self.container_name, tail)

    def execute_container_command(self, command: str) -> FlextResult[str]:
        """Execute command in container using FlextTestDocker."""
        return self.docker_manager.execute_container_command(
            self.container_name, command
        )

    def get_container_status(self) -> FlextResult[FlextTypes.StringDict]:
        """Get container status using FlextTestDocker."""
        status_result = self.docker_manager.get_container_status(self.container_name)
        if status_result.is_failure:
            error_msg = status_result.error or "Unknown error"
            return FlextResult[FlextTypes.StringDict].fail(error_msg)

        container_info: ContainerInfo = status_result.value
        return FlextResult[FlextTypes.StringDict].ok(
            {
                "name": container_info["name"],
                "status": str(container_info["status"]),  # Convert status to string
                "ports": container_info["ports"],
                "image": container_info["image"],
            }
        )


def get_test_ldap_config() -> FlextLDAPModels.ConnectionConfig:
    """Get test LDAP connection configuration."""
    admin_password = os.getenv("LDAP_TEST_ADMIN_PASSWORD", "admin123")
    return FlextLDAPModels.ConnectionConfig(
        server="ldap://localhost:3390",
        bind_dn="cn=admin,dc=flext,dc=local",
        bind_password=admin_password,
        use_ssl=False,
        timeout=30,
    )


def wait_for_ldap_server(
    host: str = "localhost",
    port: int = 3390,
    timeout_seconds: int = 60,
) -> bool:
    """Wait for LDAP server to be available."""
    import time

    start_time = time.time()
    while time.time() - start_time < timeout_seconds:
        try:
            server = FlextLDAPTypes.Server(
                host=host,
                port=port,
                use_ssl=False,
                connect_timeout=5,
            )

            conn_raw = FlextLDAPTypes.Connection(
                server=server,
                user="cn=admin,dc=flext,dc=local",
                password=os.getenv("LDAP_TEST_ADMIN_PASSWORD", "admin123"),
                auto_bind=True,
                authentication=FlextLDAPTypes.SIMPLE,
            )
            conn = conn_raw

            conn.search(
                search_base="dc=flext,dc=local",
                search_filter="(objectClass=*)",
                search_scope=FlextLDAPTypes.BASE,
            )

            conn.unbind()
            return True
        except Exception:
            time.sleep(2)

    return False

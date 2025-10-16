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

from flext_core import (
    FlextLogger,
    FlextResult,
    FlextTypes,
)
from ldap3 import BASE, SIMPLE, Connection, Server

from flext_ldap import FlextLdapModels
from flext_ldap.constants import FlextLdapConstants

# from flext_tests import FlextTestDocker  # TODO(marlonsc): [https://github.com/flext-sh/flext/issues/TBD] Import when available
from .test_data import TEST_GROUPS, TEST_OUS, TEST_USERS


class ContainerInfo(TypedDict):
    """Container information from Docker."""

    name: str
    status: object  # Status enum, but we'll access .value
    ports: str
    image: str  # Docker image name


# Temporary placeholder until FlextTestDocker is available
class FlextTestDocker:
    """Placeholder for FlextTestDocker until it's available in flext_tests."""

    def start_container(self, container_name: str) -> FlextResult[bool]:
        """Start a container with the given name."""
        return FlextResult[bool].fail("FlextTestDocker not available")

    def stop_container(
        self, container_name: str, *, remove: bool = False
    ) -> FlextResult[bool]:
        """Stop a container with the given name, optionally removing it."""
        return FlextResult[bool].fail("FlextTestDocker not available")

    def get_container_logs(
        self, container_name: str, tail: int = 100
    ) -> FlextResult[str]:
        """Get logs from a container, optionally limiting to last N lines."""
        return FlextResult[str].fail("FlextTestDocker not available")

    def execute_container_command(
        self, container_name: str, command: str
    ) -> FlextResult[str]:
        """Execute a command in a running container."""
        return FlextResult[str].fail("FlextTestDocker not available")

    def get_container_status(self, container_name: str) -> FlextResult[ContainerInfo]:
        """Get status information for a container."""
        return FlextResult[ContainerInfo].fail("FlextTestDocker not available")


class DockerManagerProtocol(Protocol):
    """Protocol for Docker manager with required methods."""

    def start_container(self, container_name: str) -> FlextResult[bool]:
        """Start a container with the given name."""
        ...

    def stop_container(self, container_name: str, remove: bool) -> FlextResult[bool]:
        """Stop a container with the given name, optionally removing it."""
        ...

    def get_container_logs(self, container_name: str, tail: int) -> FlextResult[str]:
        """Get logs from a container, optionally limiting to last N lines."""
        ...

    def execute_container_command(
        self, container_name: str, command: str
    ) -> FlextResult[str]:
        """Execute a command in a running container."""
        ...

    def get_container_status(self, container_name: str) -> FlextResult[ContainerInfo]:
        """Get status information for a container."""
        ...

    def get_docker_version(self) -> FlextResult[str]:
        """Get the Docker version information."""
        ...


logger = FlextLogger(__name__)


class LdapTestServer:
    """Manages LDAP test server using unified FlextTestDocker."""

    def __init__(
        self,
        container_name: str = "flext-openldap-test",
        port: int = 3390,
        REDACTED_LDAP_BIND_PASSWORD_password: str | None = None,
    ) -> None:
        """Initialize LDAP test server with FlextTestDocker management."""
        self.container_name = container_name
        self.port = port
        self.REDACTED_LDAP_BIND_PASSWORD_password = REDACTED_LDAP_BIND_PASSWORD_password or os.getenv(
            "LDAP_TEST_ADMIN_PASSWORD",
            "REDACTED_LDAP_BIND_PASSWORD123",
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
                server = Server(
                    host="localhost",
                    port=self.port,
                    use_ssl=False,
                    connect_timeout=5,
                )

                conn = Connection(
                    server=server,
                    user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
                    password=self.REDACTED_LDAP_BIND_PASSWORD_password,
                    auto_bind=True,
                    authentication=SIMPLE,
                )

                conn.search(
                    search_base="dc=flext,dc=local",
                    search_filter="(objectClass=*)",
                    search_scope=BASE,
                )

                conn.unbind()
                logger.info("LDAP server is ready")
                return True
            except Exception as e:
                logger.debug("LDAP server not ready yet: %s", e)
                time.sleep(FlextLdapConstants.LdapRetry.SERVER_READY_RETRY_DELAY)

        logger.error("LDAP server failed to become ready within timeout")
        return False

    def setup_test_data(self) -> FlextResult[bool]:
        """Set up initial test data in LDAP server."""
        try:
            # Connect to LDAP server
            server = Server(
                host="localhost",
                port=self.port,
                use_ssl=False,
            )

            conn = Connection(
                server=server,
                user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
                password=self.REDACTED_LDAP_BIND_PASSWORD_password,
                auto_bind=True,
                authentication=SIMPLE,
            )

            # Create organizational units first
            for ou_data in TEST_OUS:
                try:
                    # Extract objectClass from attributes
                    attrs_dict = cast("dict[str, object]", ou_data["attributes"])
                    object_class_list: list[str] = cast(
                        "list[str]", attrs_dict.get("objectClass", ["top"])
                    )
                    attrs_without_oc = {
                        k: v for k, v in attrs_dict.items() if k != "objectClass"
                    }
                    conn.add_entry(
                        cast("str", ou_data["dn"]),
                        object_class_list,
                        attributes=attrs_without_oc or None,
                    )
                    logger.debug("Created OU: %s", ou_data["dn"])
                except Exception as e:
                    logger.debug("Failed to create OU %s: %s", ou_data["dn"], e)

            # Create test users
            for user_data in TEST_USERS:
                try:
                    # Extract objectClass from attributes
                    attrs_dict = cast("dict[str, object]", user_data["attributes"])
                    object_class_list = cast(
                        "list[str]", attrs_dict.get("objectClass", ["top"])
                    )
                    attrs_without_oc = {
                        k: v for k, v in attrs_dict.items() if k != "objectClass"
                    }
                    conn.add_entry(
                        cast("str", user_data["dn"]),
                        object_class_list,
                        attributes=attrs_without_oc or None,
                    )
                    logger.debug("Created user: %s", user_data["dn"])
                except Exception as e:
                    logger.debug("Failed to create user %s: %s", user_data["dn"], e)

            # Create test groups
            for group_data in TEST_GROUPS:
                try:
                    # Extract objectClass from attributes
                    attrs_dict = cast("dict[str, object]", group_data["attributes"])
                    object_class_list = cast(
                        "list[str]", attrs_dict.get("objectClass", ["top"])
                    )
                    attrs_without_oc = {
                        k: v for k, v in attrs_dict.items() if k != "objectClass"
                    }
                    conn.add_entry(
                        cast("str", group_data["dn"]),
                        object_class_list,
                        attributes=attrs_without_oc or None,
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

    def get_connection_config(self) -> FlextLdapModels.ConnectionConfig:
        """Get connection configuration for test server."""
        return FlextLdapModels.ConnectionConfig(
            server=f"ldap://localhost:{self.port}",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            bind_password=self.REDACTED_LDAP_BIND_PASSWORD_password or "REDACTED_LDAP_BIND_PASSWORD123",
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
        return FlextResult[FlextTypes.StringDict].ok({
            "name": container_info["name"],
            "status": str(container_info["status"]),  # Convert status to string
            "ports": container_info["ports"],
            "image": container_info["image"],
        })


def get_test_ldap_config() -> FlextLdapModels.ConnectionConfig:
    """Get test LDAP connection configuration."""
    REDACTED_LDAP_BIND_PASSWORD_password = os.getenv("LDAP_TEST_ADMIN_PASSWORD", "REDACTED_LDAP_BIND_PASSWORD123")
    return FlextLdapModels.ConnectionConfig(
        server="ldap://localhost:3390",
        bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
        bind_password=REDACTED_LDAP_BIND_PASSWORD_password,
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
            server = Server(
                host=host,
                port=port,
                use_ssl=False,
                connect_timeout=5,
            )

            conn_raw = Connection(
                server=server,
                user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
                password=os.getenv("LDAP_TEST_ADMIN_PASSWORD", "REDACTED_LDAP_BIND_PASSWORD123"),
                auto_bind=True,
                authentication=SIMPLE,
            )
            conn = conn_raw

            conn.search(
                search_base="dc=flext,dc=local",
                search_filter="(objectClass=*)",
                search_scope=BASE,
            )

            conn.unbind()
            return True
        except Exception:
            time.sleep(2)

    return False

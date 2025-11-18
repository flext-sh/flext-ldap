"""Pytest configuration and fixtures for flext-ldap tests.

Reuses fixtures from tests.bak, adapted for new API structure.
Uses FlextTestDocker for container management.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Callable, Generator
from pathlib import Path

import pytest
from flext_core import FlextLogger
from flext_ldif import FlextLdifParser
from flext_tests import FlextTestDocker
from ldap3 import Connection, Server

from flext_ldap import FlextLdap
from flext_ldap.adapters.ldap3 import Ldap3Adapter
from flext_ldap.config import FlextLdapConfig
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations
from tests.fixtures.loader import LdapTestFixtures

logger = FlextLogger(__name__)

# Register FlextTestDocker pytest fixtures in this module's namespace
FlextTestDocker.register_pytest_fixtures(namespace=globals())


# =============================================================================
# PYTEST HOOKS (REGRAS 1 & 4: Container Lifecycle & Dirty State Management)
# =============================================================================


def pytest_sessionstart(session: pytest.Session) -> None:
    """Cleanup dirty containers BEFORE test session starts (REGRA 1).

    This hook executes before ANY test runs and:
    1. Checks if containers are marked dirty from previous run
    2. Recreates dirty containers with docker-compose down -v + up -d
    3. Ensures clean state for test execution

    REGRA 1: Container DEVE ser recreado TOTALMENTE se estiver dirty.
    """
    docker = FlextTestDocker()

    # Cleanup any containers marked dirty from previous run
    cleanup_result = docker.cleanup_dirty_containers()

    if cleanup_result.is_failure:
        logger.warning(f"Dirty container cleanup failed: {cleanup_result.error}")
    else:
        cleaned = cleanup_result.unwrap()
        if cleaned:
            logger.info(f"Recreated dirty containers: {cleaned}")
        else:
            logger.debug("No dirty containers to clean")


def pytest_runtest_makereport(
    item: pytest.Item,
    call: pytest.CallInfo,
) -> None:
    """Mark container dirty on LDAP service failures ONLY (REGRA 4).

    This hook executes after each test phase (setup/call/teardown) and:
    1. Checks if exception indicates LDAP SERVICE failure (not test assertion)
    2. Marks container as dirty for recreation in next run
    3. Logs the failure for debugging

    REGRA 4: APENAS falhas do serviço LDAP marcam como dirty.
    - Assertion failures (test logic) = NOT dirty
    - Connection/communication errors = dirty
    """
    if call.excinfo is None:
        return  # No exception, skip

    exc_type = call.excinfo.type
    exc_msg = str(call.excinfo.value).lower()

    # Lista de erros que indicam FALHA DO SERVIÇO LDAP (não de teste)
    ldap_service_errors = [
        "ldapsocketopenerror",
        "ldapsessionterminatedbyservererror",
        "ldapcommunicationerror",
        "ldapserverdownerror",
        "ldap server is not responding",
        "connection refused",
        "connection reset by peer",
        "broken pipe",
        "cannot connect to ldap",
        "ldap bind failed",
    ]

    # Verificar se é erro de SERVIÇO (não assertion de teste)
    is_service_failure = any(
        err in str(exc_type).lower() or err in exc_msg for err in ldap_service_errors
    )

    if is_service_failure:
        docker = FlextTestDocker()
        docker.mark_container_dirty("flext-openldap-test")
        logger.error(
            f"LDAP SERVICE FAILURE detected in {item.nodeid}, "
            f"container marked DIRTY for recreation: {exc_msg}"
        )


# =============================================================================
# BASE FIXTURES (REGRA 3: Idempotência & Paralelização)
# =============================================================================


@pytest.fixture(scope="session")
def worker_id(request: pytest.FixtureRequest) -> str:
    """Get pytest-xdist worker ID for DN namespacing (REGRA 3).

    Returns:
        str: Worker ID (e.g., "gw0", "gw1", "master")
            - "master": single-process execution
            - "gw0", "gw1", ...: parallel workers from pytest-xdist

    """
    worker_input = getattr(request.config, "workerinput", {})
    return worker_input.get("workerid", "master")


@pytest.fixture(scope="session")
def session_id() -> str:
    """Unique session ID for this test run (REGRA 3).

    Returns:
        int: Timestamp in milliseconds

    Used for DN namespacing to ensure test isolation.

    """
    import time

    return int(time.time() * 1000)


class DNSTracker:
    """Thread-safe tracker of DNs created during tests."""

    def __init__(self) -> None:
        """Initialize tracker with thread-safe structures."""
        from threading import Lock

        self._created_dns: set[str] = set()
        self._lock = Lock()

    def add(self, dn: str) -> None:
        """Add DN to tracker."""
        with self._lock:
            self._created_dns.add(dn)

    def get_all(self) -> set[str]:
        """Get all tracked DNs."""
        with self._lock:
            return self._created_dns.copy()


@pytest.fixture(scope="session")
def test_dns_tracker() -> DNSTracker:
    """Thread-safe tracker of DNs created during tests (REGRA 3).

    Tracks ALL DNs created by tests for intelligent cleanup.
    Thread-safe to support parallel test execution.

    Returns:
        DNSTracker: Object with add() and get_all() methods

    """
    # Legacy code - keeping for compatibility but DNSTracker is now a class
    from threading import Lock

    created_dns: set[str] = set()
    lock = Lock()

    class LegacyDNSTracker:
        """Thread-safe DN tracker for test cleanup."""

        def add(self, dn: str) -> None:
            """Add DN to tracking set (thread-safe)."""
            with lock:
                created_dns.add(dn)

        def get_all(self) -> set[str]:
            """Get copy of all tracked DNs (thread-safe)."""
            with lock:
                return created_dns.copy()

    return DNSTracker()


@pytest.fixture
def unique_dn_suffix(worker_id: str, session_id: str) -> str:
    """Generate unique DN suffix for this worker and test (REGRA 3).

    Combines worker ID, session ID, and microsecond timestamp to create
    globally unique DN suffix that prevents conflicts in parallel execution.

    Args:
        worker_id: pytest-xdist worker ID (e.g., "gw0", "master")
        session_id: Test session timestamp

    Returns:
        str: Unique suffix (e.g., "gw0-1733000000-123456")

    Example:
        >>> suffix = unique_dn_suffix
        >>> dn = f"uid=testuser-{suffix},ou=people,dc=flext,dc=local"

    """
    import time

    # Microsecond precision for intra-second uniqueness
    test_id = int(time.time() * 1000000) % 1000000

    return f"{worker_id}-{session_id}-{test_id}"


@pytest.fixture
def make_user_dn(unique_dn_suffix: str) -> Callable[[str], str]:
    """Factory to create unique user DNs (REGRA 3).

    Args:
        unique_dn_suffix: Unique suffix from fixture

    Returns:
        callable: Factory function that takes uid and returns unique DN

    Example:
        >>> make_dn = make_user_dn
        >>> dn = make_dn("testuser")  # uid=testuser-gw0-...,ou=people,...

    """

    def _make(uid: str) -> str:
        """Create unique user DN.

        Args:
            uid: User ID (e.g., "testuser")

        Returns:
            str: Unique DN (e.g., "uid=testuser-gw0-123...,ou=people,dc=flext,dc=local")

        """
        return f"uid={uid}-{unique_dn_suffix},ou=people,dc=flext,dc=local"

    return _make


@pytest.fixture
def make_group_dn(unique_dn_suffix: str) -> Callable[[str], str]:
    """Factory to create unique group DNs (REGRA 3).

    Args:
        unique_dn_suffix: Unique suffix from fixture

    Returns:
        callable: Factory function that takes cn and returns unique DN

    Example:
        >>> make_dn = make_group_dn
        >>> dn = make_dn("testgroup")  # cn=testgroup-gw0-...,ou=groups,...

    """

    def _make(cn: str) -> str:
        """Create unique group DN.

        Args:
            cn: Common name (e.g., "testgroup")

        Returns:
            str: Unique DN (e.g., "cn=testgroup-gw0-123...,ou=groups,dc=flext,dc=local")

        """
        return f"cn={cn}-{unique_dn_suffix},ou=groups,dc=flext,dc=local"

    return _make


# =============================================================================
# DOCKER CONTAINER FIXTURES (using FlextTestDocker)
# =============================================================================


@pytest.fixture(scope="session")
def ldap_container(
    docker_control: FlextTestDocker,  # From FlextTestDocker
) -> dict[str, object]:
    """Session-scoped LDAP container configuration.

    Uses FlextTestDocker to manage flext-openldap-test container.
    Container is automatically started/stopped by FlextTestDocker.

    Args:
        docker_control: FlextTestDocker instance from fixture

    Returns:
        dict with connection parameters

    """
    # Use the actual container name from SHARED_CONTAINERS
    container_name = "flext-openldap-test"
    container_config = FlextTestDocker.SHARED_CONTAINERS.get(container_name)

    if not container_config:
        pytest.skip(f"Container {container_name} not found in SHARED_CONTAINERS")

    # Get compose file path
    compose_file = str(container_config["compose_file"])
    if not compose_file.startswith("/"):
        # Relative path, make it absolute from workspace root
        # Workspace root is /home/marlonsc/flext
        workspace_root = Path("/home/marlonsc/flext")
        compose_file = str(workspace_root / compose_file)

    # Check if container is running, if not start it using docker-compose
    status = docker_control.get_container_status(container_name)
    if not status.is_success or (
        isinstance(status.value, FlextTestDocker.ContainerInfo)
        and status.value.status != FlextTestDocker.ContainerStatus.RUNNING
    ):
        # Container doesn't exist or not running, start it using docker-compose
        start_result = docker_control.start_compose_stack(compose_file)
        if start_result.is_failure:
            pytest.skip(f"Failed to start LDAP container: {start_result.error}")

    # Provide connection info (matches docker-compose.openldap.yml)
    container_info: dict[str, object] = {
        "server_url": "ldap://localhost:3390",
        "host": "localhost",
        "bind_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
        "password": "REDACTED_LDAP_BIND_PASSWORD123",  # From docker-compose.openldap.yml
        "base_dn": "dc=flext,dc=local",
        "port": 3390,
        "use_ssl": False,
    }

    return container_info


# =============================================================================
# CONFIGURATION FIXTURES
# =============================================================================


@pytest.fixture(scope="module")
def ldap_parser() -> FlextLdifParser:
    """Get standard LDIF parser instance for tests.

    Module-scoped to match ldap_client fixture scope for performance.
    """
    return FlextLdifParser()


@pytest.fixture(scope="module")
def ldap_config(ldap_container: dict[str, object]) -> FlextLdapConfig:
    """Get standard LDAP connection configuration.

    Module-scoped to match ldap_client fixture scope for performance.
    """
    port_value = ldap_container["port"]
    port_int = int(port_value) if isinstance(port_value, (int, str)) else 3390

    return FlextLdapConfig(
        ldap_host=str(ldap_container["host"]),
        ldap_port=port_int,
        ldap_use_ssl=False,
        ldap_bind_dn=str(ldap_container["bind_dn"]),
        ldap_bind_password=str(ldap_container["password"]),
    )


@pytest.fixture(scope="module")
def connection_config(
    ldap_container: dict[str, object],
) -> FlextLdapModels.ConnectionConfig:
    """Create connection configuration for testing.

    Module-scoped to match ldap_client fixture scope for performance.
    """
    port_value = ldap_container["port"]
    port_int = int(port_value) if isinstance(port_value, (int, str)) else 3390

    return FlextLdapModels.ConnectionConfig(
        host=str(ldap_container["host"]),
        port=port_int,
        use_ssl=False,
        bind_dn=str(ldap_container["bind_dn"]),
        bind_password=str(ldap_container["password"]),
    )


@pytest.fixture
def search_options(ldap_container: dict[str, object]) -> FlextLdapModels.SearchOptions:
    """Create search options for testing."""
    return FlextLdapModels.SearchOptions(
        base_dn=str(ldap_container["base_dn"]),
        filter_str="(objectClass=*)",
        scope="SUBTREE",
    )


# =============================================================================
# LDAP CLIENT FIXTURES
# =============================================================================


@pytest.fixture(scope="module")
def ldap_client(
    connection_config: FlextLdapModels.ConnectionConfig,
    ldap_test_data_loader: Connection,
    ldap_config: FlextLdapConfig,
    ldap_parser: FlextLdifParser,
    docker_control: FlextTestDocker,
) -> Generator[FlextLdap]:
    """Get configured LDAP client with REAL connection and dirty detection (REGRAS 3 & 4).

    Module-scoped to reuse connection across tests in same module for performance.
    Tests should clean up their own data to avoid state corruption.
    Ensures OUs exist via ldap_test_data_loader fixture.

    REGRA 3: Uses REAL LDAP connection (NO MOCKS).
    REGRA 4: Marks container dirty on connection/service failures.

    Args:
        connection_config: Connection configuration
        ldap_test_data_loader: Ensures OUs exist
        ldap_config: LDAP config
        ldap_parser: LDIF parser
        docker_control: Docker control for dirty state marking

    Yields:
        FlextLdap: REAL LDAP client instance (NO MOCKS)

    """
    # Ensure OUs exist (ldap_test_data_loader creates them)
    _ = ldap_test_data_loader

    # Create REAL FlextLdap instance (NO MOCKS)
    client = FlextLdap(config=ldap_config, parser=ldap_parser)

    # REAL connection attempt
    connect_result = client.connect(connection_config)

    if connect_result.is_failure:
        # Connection failure = LDAP service problem = mark dirty (REGRA 4)
        docker_control.mark_container_dirty("flext-openldap-test")
        pytest.skip(
            f"LDAP connection failed, container marked DIRTY: {connect_result.error}"
        )

    yield client  # REAL client object

    # REAL disconnect - mark dirty if fails (potential service issue)
    try:
        client.disconnect()
    except Exception as e:
        logger.warning(f"LDAP client disconnection failed (marking dirty): {e}")
        docker_control.mark_container_dirty("flext-openldap-test")


# =============================================================================
# TEST DATA FIXTURES
# =============================================================================


@pytest.fixture(scope="session")
def ldap_test_data_loader(
    ldap_container: dict[str, object],
    test_dns_tracker: DNSTracker,
) -> Generator[Connection]:
    """Session-scoped test data loader with intelligent cleanup (REGRA 3).

    Creates REAL LDAP connection (NO MOCKS) and initializes base test structure.
    Tracks ALL DNs created during tests for intelligent cleanup.

    REGRA 3: Cleanup inteligente de TODOS os DNs rastreados (não lista hardcoded).

    Args:
        ldap_container: Container connection info
        test_dns_tracker: DN tracker for intelligent cleanup

    Yields:
        Connection: REAL ldap3 connection to LDAP container

    Uses FlextTestDocker managed container.

    """
    try:
        # Create REAL connection to LDAP server (NO MOCKS)
        server = Server("ldap://localhost:3390", get_info="ALL")
        connection = Connection(
            server,
            user=str(ldap_container["bind_dn"]),
            password=str(ldap_container["password"]),
            auto_bind=True,  # REAL bind
            auto_referrals=False,
        )

        # Create organizational units with REAL LDAP operations
        ous = [
            ("ou=people,dc=flext,dc=local", "people"),
            ("ou=groups,dc=flext,dc=local", "groups"),
            ("ou=system,dc=flext,dc=local", "system"),
        ]

        for ou_dn, ou_name in ous:
            try:
                _ = connection.add(  # REAL add operation
                    ou_dn,
                    attributes={
                        "objectClass": ["organizationalUnit", "top"],
                        "ou": ou_name,
                    },
                )
            except Exception:
                pass  # OU might already exist

        yield connection  # REAL connection object

        # INTELLIGENT CLEANUP: Delete ALL tracked DNs (REGRA 3)
        try:
            all_dns = test_dns_tracker.get_all()
            logger.info(f"Cleaning up {len(all_dns)} tracked DNs from tests")

            for dn in all_dns:
                try:
                    _ = connection.delete(dn)  # REAL delete operation
                    logger.debug(f"Cleaned up DN: {dn}")
                except Exception as e:
                    # Entry might be already deleted by test or not exist
                    logger.debug(f"Cleanup skip for {dn}: {e}")

        except Exception as e:
            logger.warning(f"Cleanup failed (non-critical): {e}")

        # Close REAL connection
        if connection.bound:
            connection.unbind()

    except Exception as e:
        logger.exception("Failed to initialize test data loader")
        pytest.skip(f"Test data loader initialization failed: {e!s}")


# =============================================================================
# FIXTURE DATA LOADERS
# =============================================================================


@pytest.fixture
def test_users_json() -> list[dict[str, object]]:
    """Load test users from JSON fixture file."""
    return LdapTestFixtures.load_users_json()


@pytest.fixture
def test_groups_json() -> list[dict[str, object]]:
    """Load test groups from JSON fixture file."""
    return LdapTestFixtures.load_groups_json()


@pytest.fixture
def base_ldif_content() -> str:
    """Load base LDIF structure from fixture file."""
    return LdapTestFixtures.load_base_ldif()


@pytest.fixture
def base_ldif_entries() -> list[object]:
    """Load and parse base LDIF structure to Entry models."""
    return LdapTestFixtures.load_base_ldif_entries()


@pytest.fixture
def test_user_entry(test_users_json: list[dict[str, object]]) -> dict[str, object]:
    """Get first test user as Entry-compatible dict."""
    if not test_users_json:
        pytest.skip("No test users available")

    return LdapTestFixtures.convert_user_json_to_entry(test_users_json[0])


@pytest.fixture
def test_group_entry(test_groups_json: list[dict[str, object]]) -> dict[str, object]:
    """Get first test group as Entry-compatible dict."""
    if not test_groups_json:
        pytest.skip("No test groups available")

    return LdapTestFixtures.convert_group_json_to_entry(test_groups_json[0])


# =============================================================================
# SAMPLE TEST DATA
# =============================================================================


SAMPLE_USER_ENTRY = {
    "dn": "cn=testuser,ou=people,dc=flext,dc=local",
    "attributes": {
        "cn": ["testuser"],
        "sn": ["User"],
        "givenName": ["Test"],
        "uid": ["testuser"],
        "mail": ["testuser@internal.invalid"],
        "objectClass": ["inetOrgPerson", "organizationalPerson", "person", "top"],
        "userPassword": ["test123"],
    },
}

SAMPLE_GROUP_ENTRY = {
    "dn": "cn=testgroup,ou=groups,dc=flext,dc=local",
    "attributes": {
        "cn": ["testgroup"],
        "objectClass": ["groupOfNames", "top"],
        "member": ["cn=testuser,ou=people,dc=flext,dc=local"],
    },
}


@pytest.fixture
def ldap_connection(
    ldap_config: FlextLdapConfig,
    ldap_parser: FlextLdifParser,
) -> FlextLdapConnection:
    """Get FlextLdapConnection instance for testing."""
    return FlextLdapConnection(config=ldap_config, parser=ldap_parser)


@pytest.fixture
def ldap_operations(ldap_connection: FlextLdapConnection) -> FlextLdapOperations:
    """Get FlextLdapOperations instance for testing."""
    return FlextLdapOperations(connection=ldap_connection)


@pytest.fixture
def ldap3_adapter(ldap_parser: FlextLdifParser) -> Ldap3Adapter:
    """Get Ldap3Adapter instance for testing."""
    return Ldap3Adapter(parser=ldap_parser)


@pytest.fixture
def flext_ldap_instance(
    ldap_config: FlextLdapConfig,
    ldap_parser: FlextLdifParser,
) -> FlextLdap:
    """Get FlextLdap instance without connection."""
    return FlextLdap(config=ldap_config, parser=ldap_parser)

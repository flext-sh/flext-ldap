"""Pytest configuration and fixtures for flext-ldap tests.

Reuses fixtures from tests.bak, adapted for new API structure.
Uses FlextTestDocker for container management.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Container Lifecycle Rules:
- Container is started/recreated at session start (if dirty or not running)
- Container stays running after tests complete (NO teardown stop)
- Container is marked dirty ONLY for real LDAP service failures (not test assertions)
- Dirty containers are recreated on next session start

"""

from __future__ import annotations

import fcntl
import time
import types
from collections.abc import Callable, Generator
from pathlib import Path
from threading import Lock
from typing import TextIO, cast

import pytest
from flext_core import FlextLogger
from flext_ldif import FlextLdif, FlextLdifModels
from flext_ldif.services.parser import FlextLdifParser
from flext_tests import FlextTestDocker
from ldap3 import Connection, Server

from flext_ldap.api import FlextLdap
from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.operations import FlextLdapOperations
from tests.fixtures.typing import GenericFieldsDict, LdapContainerDict

from .fixtures import LdapTestFixtures

logger = FlextLogger(__name__)

# =============================================================================
# CONSTANTS - Container and workspace configuration
# =============================================================================

# FLEXT-LDAP project root (absolute path for consistent workspace_root)
FLEXT_LDAP_ROOT = Path(__file__).parent.parent.resolve()
FLEXT_WORKSPACE_ROOT = FLEXT_LDAP_ROOT.parent  # /home/marlonsc/flext

# Container configuration (matches SHARED_CONTAINERS in FlextTestDocker)
LDAP_CONTAINER_NAME = "flext-openldap-test"
LDAP_COMPOSE_FILE = FLEXT_WORKSPACE_ROOT / "docker" / "docker-compose.openldap.yml"
LDAP_SERVICE_NAME = "openldap"
LDAP_PORT = 3390
LDAP_BASE_DN = "dc=flext,dc=local"
LDAP_ADMIN_DN = "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local"
LDAP_ADMIN_PASSWORD = "REDACTED_LDAP_BIND_PASSWORD123"  # Matches docker-compose.openldap.yml


# =============================================================================
# TYPED WRAPPERS FOR LDAP3 UNTYPED METHODS (mypy strict compatibility)
# =============================================================================


def _ldap3_add(
    conn: Connection,
    dn: str,
    object_class: str | list[str] | None = None,
    attributes: dict[str, list[str]] | None = None,
) -> bool:
    """Typed wrapper for Connection.add."""
    add_func: Callable[..., bool] = conn.add
    return add_func(dn, object_class, attributes)


def _ldap3_delete(conn: Connection, dn: str) -> bool:
    """Typed wrapper for Connection.delete."""
    delete_func: Callable[[str], bool] = conn.delete
    return delete_func(dn)


def _ldap3_unbind(conn: Connection) -> None:
    """Typed wrapper for Connection.unbind."""
    unbind_func: Callable[[], None] = conn.unbind
    unbind_func()


def _get_docker_control(worker_id: str = "master") -> FlextTestDocker:
    """Create FlextTestDocker with correct workspace root for flext-ldap.

    Uses FLEXT_WORKSPACE_ROOT to ensure docker-compose paths resolve correctly.
    The compose file is at docker/docker-compose.openldap.yml relative to workspace root.

    Args:
        worker_id: pytest-xdist worker ID for parallel execution isolation

    Returns:
        FlextTestDocker instance with correct workspace_root

    """
    return FlextTestDocker(
        workspace_root=FLEXT_WORKSPACE_ROOT,
        worker_id=worker_id,
    )


# NOTE: We do NOT call FlextTestDocker.register_pytest_fixtures() here
# because those fixtures (flext_ldap_container, etc.) have teardown that
# STOPS the container after tests. We want the container to stay running.
# Our custom ldap_container fixture handles lifecycle correctly.


class FileLock:
    """File-based locking for pytest-xdist parallel execution."""

    def __init__(self, lock_file: Path) -> None:
        """Initialize file lock.

        Args:
            lock_file: Path to the lock file

        """
        self.lock_file = lock_file
        self._fd: int | None = None
        self._file_obj: TextIO | None = None

    def __enter__(self) -> None:
        """Acquire the file lock."""
        self.lock_file.parent.mkdir(parents=True, exist_ok=True)
        self._file_obj = self.lock_file.open("w")
        self._fd = self._file_obj.fileno()
        fcntl.flock(self._fd, fcntl.LOCK_EX)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        """Release the file lock."""
        if self._fd is not None:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        if self._file_obj is not None:
            self._file_obj.close()
        self.lock_file.unlink(missing_ok=True)


# =============================================================================
# PYTEST HOOKS (REGRAS 1 & 4: Container Lifecycle & Dirty State Management)
# =============================================================================


def pytest_sessionstart(session: pytest.Session) -> None:
    """Cleanup dirty containers and ensure LDAP is ready BEFORE tests start.

    This hook executes before ANY test runs and:
    1. Checks if LDAP container is marked dirty from previous run
    2. Recreates dirty containers with docker-compose down -v + up -d
    3. Starts container if stopped (but not dirty) using start_existing_container
    4. Creates container if not exists using compose up

    Container STAYS RUNNING after tests - no teardown stop.

    """
    # Get worker ID for isolation
    worker_input = getattr(session.config, "workerinput", {})
    worker_id = str(worker_input.get("workerid", "master"))

    # Use helper with correct workspace_root
    docker_control = _get_docker_control(worker_id)

    # Check if LDAP container is dirty
    is_dirty = docker_control.is_container_dirty(LDAP_CONTAINER_NAME)

    if is_dirty:
        logger.info(
            "Container %s is dirty, recreating with fresh volumes",
            LDAP_CONTAINER_NAME,
        )
        # Use relative path from workspace_root
        compose_file_rel = str(LDAP_COMPOSE_FILE.relative_to(FLEXT_WORKSPACE_ROOT))
        compose_result = docker_control.compose_down(compose_file_rel)
        if compose_result.is_failure:
            logger.warning(f"Compose down failed: {compose_result.error}")
        create_result = docker_control.compose_up(
            compose_file_rel,
            service=LDAP_SERVICE_NAME,
            force_recreate=True,
        )
        if create_result.is_failure:
            logger.warning(f"Container recreate failed: {create_result.error}")
        else:
            docker_control.mark_container_clean(LDAP_CONTAINER_NAME)
            logger.info("Recreated dirty container: %s", LDAP_CONTAINER_NAME)
    else:
        # Not dirty - try to start existing container first (without recreation)
        start_result = docker_control.start_existing_container(LDAP_CONTAINER_NAME)

        if start_result.is_success:
            logger.info(f"Container {LDAP_CONTAINER_NAME}: {start_result.value}")
        else:
            # Container doesn't exist - create it with compose_up
            logger.info(
                "Container %s not found, creating with compose...",
                LDAP_CONTAINER_NAME,
            )
            compose_file_rel = str(LDAP_COMPOSE_FILE.relative_to(FLEXT_WORKSPACE_ROOT))
            create_result = docker_control.compose_up(
                compose_file_rel,
                service=LDAP_SERVICE_NAME,
            )
            if create_result.is_failure:
                logger.warning(f"Container create failed: {create_result.error}")
            else:
                logger.info("Container %s created", LDAP_CONTAINER_NAME)


def pytest_runtest_makereport(
    item: pytest.Item,
    call: pytest.CallInfo[None],
) -> None:
    """Mark container dirty on LDAP infrastructure failures ONLY.

    This hook executes after each test phase (setup/call/teardown) and:
    1. Checks if exception indicates LDAP INFRASTRUCTURE failure (not test assertion)
    2. Marks container as dirty for recreation in next session
    3. Does NOT stop the container - just marks for future recreation

    Rules for marking dirty:
    - Assertion failures (test logic errors) = NOT dirty
    - Connection refused/reset = NOT dirty (timing, not infrastructure)
    - Server terminated session unexpectedly = DIRTY (infrastructure broken)
    - Server down or unresponsive = DIRTY (infrastructure broken)

    """
    if call.excinfo is None:
        return  # No exception, skip

    exc_type = call.excinfo.type
    exc_msg = str(call.excinfo.value).lower()
    exc_type_str = str(exc_type).lower()

    # Infrastructure errors that indicate the container itself is broken
    # These require full container recreation (down -v + up)
    infrastructure_errors = [
        "ldapsessionterminatedbyservererror",  # Server unexpectedly closed session
        "ldapserverdownerror",  # Server process crashed
        "ldap server is not responding",  # Server hung
        "broken pipe",  # Socket broken
        "session terminated by server",  # Unexpected termination
        "ldapoperationresult",  # Server returned operation error
    ]

    # Connection errors are usually transient (timing, network, startup)
    # Do NOT mark dirty - container may just need a moment
    transient_errors = [
        "connection refused",  # Container not yet ready
        "connection reset by peer",  # Brief network glitch
        "cannot connect to ldap",  # Temporary connectivity
        "ldapsocketopenerror",  # Socket not yet available
        "ldapcommunicationerror",  # Brief communication issue
        "ldap bind failed",  # Auth timing issue
        "timeout",  # Just slow, not broken
    ]

    # Check if this is a real infrastructure failure
    is_infrastructure_failure = any(
        err in exc_type_str or err in exc_msg for err in infrastructure_errors
    )

    # Check if this is a transient error (don't mark dirty)
    is_transient = any(
        err in exc_type_str or err in exc_msg for err in transient_errors
    )

    if is_infrastructure_failure and not is_transient:
        # Get worker ID for isolation
        worker_input = getattr(item.session.config, "workerinput", {})
        worker_id = str(worker_input.get("workerid", "master"))

        # Use helper with correct workspace_root
        docker = _get_docker_control(worker_id)
        docker.mark_container_dirty(LDAP_CONTAINER_NAME)

        logger.error(
            f"LDAP INFRASTRUCTURE FAILURE in {item.nodeid}, "
            f"container marked DIRTY for recreation on next session: {exc_msg}",
        )
    elif is_transient:
        logger.warning(
            f"LDAP transient error in {item.nodeid} (not marking dirty): {exc_msg}",
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
    return cast("str", worker_input.get("workerid", "master"))


@pytest.fixture(scope="session")
def session_id() -> str:
    """Unique session ID for this test run (REGRA 3).

    Returns:
        str: Timestamp in milliseconds as string

    Used for DN namespacing to ensure test isolation.

    """
    return str(int(time.time() * 1000))


class DNSTracker:
    """Thread-safe tracker of DNs created during tests."""

    def __init__(self) -> None:
        """Initialize tracker with thread-safe structures."""
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
    return DNSTracker()


@pytest.fixture
def unique_dn_suffix(
    worker_id: str,
    session_id: str,
    request: pytest.FixtureRequest,
) -> str:
    """Generate unique DN suffix for this worker and test (REGRA 3).

    Combines worker ID, session ID, test function name, and microsecond timestamp
    to create globally unique DN suffix that prevents conflicts in parallel execution.
    This ensures complete isolation between tests even when running in parallel.

    Args:
        worker_id: pytest-xdist worker ID (e.g., "gw0", "master")
        session_id: Test session timestamp
        request: Pytest request object for test identification

    Returns:
        str: Unique suffix (e.g., "gw0-1733000000-test_function-123456")

    Example:
        >>> suffix = unique_dn_suffix
        >>> dn = f"uid=testuser-{suffix},ou=people,dc=flext,dc=local"

    """
    # Get test function name for additional isolation
    test_name = request.node.name if hasattr(request, "node") else "unknown"
    # Sanitize test name (remove special chars that could break DN)
    allowed_chars = {"-", "_"}
    test_name_clean = "".join(
        c if c.isalnum() or c in allowed_chars else "-" for c in test_name
    )[:20]

    # Microsecond precision for intra-second uniqueness
    test_id = int(time.time() * 1000000) % 1000000

    return f"{worker_id}-{session_id}-{test_name_clean}-{test_id}"


@pytest.fixture
def make_user_dn(
    unique_dn_suffix: str,
    ldap_container: LdapContainerDict,
) -> Callable[[str], str]:
    """Factory to create unique user DNs with base DN isolation (REGRA 3).

    Uses the base_dn from ldap_container to ensure complete isolation.
    This allows multiple tests to run in parallel without conflicts.

    Args:
        unique_dn_suffix: Unique suffix from fixture
        ldap_container: Container configuration with base_dn

    Returns:
        callable: Factory function that takes uid and returns unique DN

    Example:
        >>> make_dn = make_user_dn
        >>> dn = make_dn("testuser")  # uid=testuser-gw0-...,ou=people,dc=flext,dc=local

    """
    base_dn = str(ldap_container.get("base_dn", "dc=flext,dc=local"))

    def _make(uid: str) -> str:
        """Create unique user DN.

        Args:
            uid: User ID (e.g., "testuser")

        Returns:
            str: Unique DN (e.g., "uid=testuser-gw0-123...,ou=people,dc=flext,dc=local")

        """
        return f"uid={uid}-{unique_dn_suffix},ou=people,{base_dn}"

    return _make


@pytest.fixture
def make_group_dn(
    unique_dn_suffix: str,
    ldap_container: LdapContainerDict,
) -> Callable[[str], str]:
    """Factory to create unique group DNs with base DN isolation (REGRA 3).

    Uses the base_dn from ldap_container to ensure complete isolation.
    This allows multiple tests to run in parallel without conflicts.

    Args:
        unique_dn_suffix: Unique suffix from fixture
        ldap_container: Container configuration with base_dn

    Returns:
        callable: Factory function that takes cn and returns unique DN

    Example:
        >>> make_dn = make_group_dn
        >>> dn = make_dn(
        ...     "testgroup"
        ... )  # cn=testgroup-gw0-...,ou=groups,dc=flext,dc=local

    """
    base_dn = str(ldap_container.get("base_dn", "dc=flext,dc=local"))

    def _make(cn: str) -> str:
        """Create unique group DN.

        Args:
            cn: Common name (e.g., "testgroup")

        Returns:
            str: Unique DN (e.g., "cn=testgroup-gw0-123...,ou=groups,dc=flext,dc=local")

        """
        return f"cn={cn}-{unique_dn_suffix},ou=groups,{base_dn}"

    return _make


# =============================================================================
# DOCKER CONTAINER FIXTURES (using FlextTestDocker)
# =============================================================================


@pytest.fixture(scope="session")
def ldap_container(
    worker_id: str,  # For isolation
) -> LdapContainerDict:
    """Session-scoped LDAP container configuration with worker isolation.

    Container lifecycle is managed by pytest_sessionstart hook:
    - Container is started/recreated at session start
    - Container STAYS RUNNING after tests complete (NO teardown stop)
    - Container is marked dirty only for infrastructure failures

    This fixture:
    1. Waits for container to be ready (LDAP connection test)
    2. Ensures basic LDAP structure exists
    3. Returns connection parameters

    All tests share the SAME container but use unique DNs for isolation.
    FIXED PORT 3390 - NO random ports, NO dynamic containers.

    Args:
        worker_id: Worker ID for logging (e.g., "gw0", "master")

    Returns:
        dict with connection parameters

    """
    # File-based locking for parallel execution support
    lock_file = Path.home() / ".flext" / f"{LDAP_CONTAINER_NAME}.lock"
    lock = FileLock(lock_file)

    # Wait for container to be ready (started by pytest_sessionstart)
    docker_control = _get_docker_control(worker_id)

    with lock:
        max_wait: int = 90  # seconds - increased for LDAP initialization
        wait_interval: float = 2.0  # seconds

        logger.info("Waiting for container %s to be ready...", LDAP_CONTAINER_NAME)

        # Step 1: Wait for port to be accessible
        port_result = docker_control.wait_for_port_ready(
            "localhost",
            LDAP_PORT,
            max_wait,
        )
        if port_result.is_failure or not port_result.value:
            pytest.skip(
                f"Container {LDAP_CONTAINER_NAME} port {LDAP_PORT} not ready "
                f"within {max_wait}s: {port_result.error or 'timeout'}",
            )

        # Step 2: Wait for LDAP service to accept connections and bind
        waited: float = 0.0
        ldap_ready = False

        while waited < max_wait:
            try:
                server = Server(
                    f"ldap://localhost:{LDAP_PORT}",
                    get_info="NO_INFO",
                )
                test_conn = Connection(
                    server,
                    user=LDAP_ADMIN_DN,
                    password=LDAP_ADMIN_PASSWORD,
                    auto_bind=True,
                    receive_timeout=5,  # Increased timeout for bind
                )
                # Verify connection is actually bound
                if test_conn.bound:
                    _ldap3_unbind(test_conn)
                    logger.info(
                        f"Container {LDAP_CONTAINER_NAME} is ready after {waited:.1f}s",
                    )
                    ldap_ready = True
                    break
            except Exception as e:
                # Container not ready yet, keep waiting
                if waited % 10 == 0:  # Log every 10 seconds
                    logger.debug(
                        f"Container {LDAP_CONTAINER_NAME} not ready yet "
                        f"(waited {waited:.1f}s): {e}",
                    )

            time.sleep(wait_interval)
            waited += wait_interval

        if not ldap_ready:
            pytest.skip(
                f"Container {LDAP_CONTAINER_NAME} LDAP service not ready "
                f"within {max_wait}s",
            )

    # Ensure basic LDAP structure exists
    with lock:
        _ensure_basic_ldap_structure()

    # Return connection info (matches docker-compose.yml)

    container_info: LdapContainerDict = {
        "server_url": f"ldap://localhost:{LDAP_PORT}",
        "host": "localhost",
        "bind_dn": LDAP_ADMIN_DN,
        "password": LDAP_ADMIN_PASSWORD,
        "base_dn": LDAP_BASE_DN,
        "port": LDAP_PORT,
        "use_ssl": False,
        "worker_id": worker_id,
    }

    logger.info(
        "LDAP container configured for worker %s: %s on port %s",
        worker_id,
        LDAP_CONTAINER_NAME,
        LDAP_PORT,
    )

    # NO TEARDOWN - container stays running after tests
    return container_info


# =============================================================================
# CONFIGURATION FIXTURES
# =============================================================================


@pytest.fixture(scope="module")
def ldap_parser() -> FlextLdifParser:
    """Get LDIF parser instance for tests.

    Module-scoped to match ldap_client fixture scope for performance.
    Returns real parser for integration tests, mock for unit tests.
    """
    # Return real parser for integration tests
    ldif = FlextLdif.get_instance()
    return ldif.parser


@pytest.fixture
def sample_connection_config() -> FlextLdapModels.ConnectionConfig:
    """Create simple connection config for unit tests (no Docker dependency).

    This is a lightweight fixture for unit tests without live LDAP connection.
    For integration tests with real LDAP server, use the 'connection_config' fixture instead.
    """
    return FlextLdapModels.ConnectionConfig(
        host="localhost",
        port=3390,
        use_ssl=False,
        bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=local",
        bind_password="test123",
    )


@pytest.fixture(scope="module")
def ldap_config(ldap_container: LdapContainerDict) -> FlextLdapConfig:
    """Get standard LDAP connection configuration.

    Module-scoped to match ldap_client fixture scope for performance.
    """
    port_value = ldap_container["port"]
    port_int = int(port_value) if isinstance(port_value, (int, str)) else 3390

    return FlextLdapConfig(
        host=str(ldap_container["host"]),
        port=port_int,
        use_ssl=False,
        bind_dn=str(ldap_container["bind_dn"]),
        bind_password=str(ldap_container["password"]),
    )


@pytest.fixture(scope="module")
def connection_config(
    ldap_container: LdapContainerDict,
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
def search_options(ldap_container: LdapContainerDict) -> FlextLdapModels.SearchOptions:
    """Create search options for testing."""
    base_dn = str(ldap_container.get("base_dn", "dc=example,dc=com"))
    return FlextLdapModels.SearchOptions(
        base_dn=base_dn,
        filter_str="(objectClass=*)",
        scope=FlextLdapConstants.SearchScope.SUBTREE,
    )


# =============================================================================
# LDAP CLIENT FIXTURES
# =============================================================================
# # Ensure OUs exist (ldap_test_data_loader creates them)
# _ = ldap_test_data_loader
#
# # Create REAL FlextLdap instance (NO MOCKS)
# client = FlextLdap(config=ldap_config, parser=ldap_parser)
#
# # REAL connection attempt
# connect_result = client.connect(connection_config)
#
# if connect_result.is_failure:
#     # Connection failure = LDAP service problem = mark dirty (REGRA 4)
#     docker_control.mark_container_dirty("flext-openldap-test")
#     pytest.skip(
#         f"LDAP connection failed, container marked DIRTY: {connect_result.error}"
#     )
#
# yield client  # REAL client object
#
# # REAL disconnect - mark dirty if fails (potential service issue)
# try:
#     client.disconnect()
# except Exception as e:
#     logger.warning(f"LDAP client disconnection failed (marking dirty): {e}")
#     docker_control.mark_container_dirty("flext-openldap-test")


# @pytest.fixture(scope="module")
# def ldap_client(
#     connection_config: FlextLdapModels.ConnectionConfig,
#     ldap_config: FlextLdapConfig,
#     ldap_parser: FlextLdifParser | None,
# ) -> FlextLdap:
#     """Get configured LDAP client instance for testing with established connection.
#
#     Creates a FlextLdap instance, connects to the LDAP server, and returns the client.
#     This enables real integration tests with actual LDAP operations.
#
#     Args:
#         connection_config: Connection configuration for LDAP server
#         ldap_config: LDAP configuration
#         ldap_parser: LDIF parser (optional)
#
#     Returns:
#         FlextLdap: Connected LDAP client instance
#
#     """
#     client = FlextLdap(config=ldap_config, parser=ldap_parser)
#
#     # Establish connection to LDAP server
#     connect_result = client.connect(connection_config)
#     if connect_result.is_failure:
#         pytest.fail(f"Failed to connect to LDAP server: {connect_result.error}")
#
#     return client


# =============================================================================
# TEST DATA FIXTURES
# =============================================================================


@pytest.fixture(scope="session")
def ldap_test_data_loader(
    ldap_container: LdapContainerDict,
    test_dns_tracker: DNSTracker,
) -> Generator[Connection]:
    """Session-scoped test data loader with intelligent cleanup.

    Creates REAL LDAP connection (NO MOCKS) and initializes base test structure.
    Tracks ALL DNs created during tests for intelligent cleanup at session end.

    Args:
        ldap_container: Container connection info
        test_dns_tracker: DN tracker for intelligent cleanup

    Yields:
        Connection: REAL ldap3 connection to LDAP container

    """
    try:
        # Create REAL connection to LDAP server (NO MOCKS)
        server = Server(f"ldap://localhost:{LDAP_PORT}", get_info="ALL")
        connection = Connection(
            server,
            user=str(ldap_container["bind_dn"]),
            password=str(ldap_container["password"]),
            auto_bind=True,  # REAL bind
            auto_referrals=False,
        )

        # Create organizational units with REAL LDAP operations
        ous = [
            (f"ou=people,{LDAP_BASE_DN}", "people"),
            (f"ou=groups,{LDAP_BASE_DN}", "groups"),
            (f"ou=system,{LDAP_BASE_DN}", "system"),
        ]

        for ou_dn, ou_name in ous:
            try:
                _ = _ldap3_add(
                    connection,
                    ou_dn,
                    attributes={
                        "objectClass": ["organizationalUnit", "top"],
                        "ou": [ou_name],
                    },
                )
            except Exception:
                pass  # OU might already exist

        yield connection  # REAL connection object

        # INTELLIGENT CLEANUP: Delete ALL tracked DNs at session end
        try:
            all_dns = test_dns_tracker.get_all()
            logger.info(f"Cleaning up {len(all_dns)} tracked DNs from tests")

            for dn in all_dns:
                try:
                    _ = _ldap3_delete(connection, dn)
                    logger.debug("Cleaned up DN: %s", dn)
                except Exception as e:
                    # Entry might be already deleted by test or not exist
                    # str() required: Exception is not GeneralValueType for debug()
                    logger.debug("Cleanup skip for %s: %s", dn, str(e))  # noqa: RUF065

        except Exception as e:
            logger.warning("Cleanup failed (non-critical)", error=e)

        # Close REAL connection
        if connection.bound:
            _ldap3_unbind(connection)

    except Exception as e:
        logger.exception("Failed to initialize test data loader")
        pytest.skip(f"Test data loader initialization failed: {e!s}")


# =============================================================================
# FIXTURE DATA LOADERS
# =============================================================================


@pytest.fixture
def test_users_json() -> list[GenericFieldsDict]:
    """Load test users from JSON fixture file."""
    return LdapTestFixtures.load_users_json()


@pytest.fixture
def test_groups_json() -> list[GenericFieldsDict]:
    """Load test groups from JSON fixture file."""
    return LdapTestFixtures.load_groups_json()


@pytest.fixture
def base_ldif_content() -> str:
    """Load base LDIF structure from fixture file."""
    return LdapTestFixtures.load_base_ldif()


@pytest.fixture
def base_ldif_entries() -> list[FlextLdifModels.Entry]:
    """Load and parse base LDIF structure to Entry models."""
    return LdapTestFixtures.load_base_ldif_entries()


@pytest.fixture
def test_user_entry(test_users_json: list[GenericFieldsDict]) -> GenericFieldsDict:
    """Get first test user as Entry-compatible dict."""
    if not test_users_json:
        pytest.skip("No test users available")

    return cast(
        "GenericFieldsDict",
        LdapTestFixtures.convert_user_json_to_entry(test_users_json[0]),
    )


@pytest.fixture
def test_group_entry(test_groups_json: list[GenericFieldsDict]) -> GenericFieldsDict:
    """Get first test group as Entry-compatible dict."""
    if not test_groups_json:
        pytest.skip("No test groups available")

    return cast(
        "GenericFieldsDict",
        LdapTestFixtures.convert_group_json_to_entry(test_groups_json[0]),
    )


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
    ldap_parser: FlextLdifParser | None,
    ldap_container: LdapContainerDict,
) -> Generator[FlextLdapConnection]:
    """Get FlextLdapConnection instance with established connection for testing.

    Creates a FlextLdapConnection, establishes a real connection to LDAP server,
    and yields the connected object for tests.
    Properly disconnects on teardown.

    Args:
        ldap_config: LDAP configuration
        ldap_parser: LDIF parser (optional)
        ldap_container: Container configuration (ensures container is ready first)

    Yields:
        FlextLdapConnection: Connected LDAP connection object

    """
    connection = FlextLdapConnection(config=ldap_config, parser=ldap_parser)

    # Establish actual connection to LDAP server
    try:
        connection_config = FlextLdapModels.ConnectionConfig(
            host=ldap_config.host,
            port=ldap_config.port,
            use_ssl=ldap_config.use_ssl,
            bind_dn=ldap_config.bind_dn,
            bind_password=ldap_config.bind_password,
        )

        connect_result = connection.connect(connection_config)

        if connect_result.is_failure:
            logger.error(f"Failed to connect to LDAP: {connect_result.error}")
            pytest.skip(f"LDAP connection failed: {connect_result.error}")

        yield connection

    except Exception as e:
        logger.exception("Error in ldap_connection fixture")
        pytest.skip(f"LDAP connection fixture error: {e}")

    finally:
        # Cleanup: disconnect from LDAP server
        try:
            connection.disconnect()
        except Exception as cleanup_error:
            logger.warning("Error during LDAP disconnect", error=cleanup_error)


@pytest.fixture
def ldap3_connection(
    ldap_container: LdapContainerDict,
) -> Generator[Connection]:
    """Create real ldap3.Connection for testing.

    Provides direct ldap3.Connection for tests that need low-level ldap3 API access.
    Reuses container configuration from ldap_container fixture.

    Args:
        ldap_container: Container configuration

    Yields:
        Connection: Connected ldap3.Connection object

    """
    server = Server(
        f"ldap://{ldap_container['host']}:{ldap_container['port']}",
        get_info="ALL",
    )
    connection = Connection(
        server,
        user=str(ldap_container["bind_dn"]),
        password=str(ldap_container["password"]),
        auto_bind=True,
    )
    yield connection
    if connection.bound:
        unbind_func: Callable[[], None] = connection.unbind
        unbind_func()


@pytest.fixture
def ldap_operations(ldap_connection: FlextLdapConnection) -> FlextLdapOperations:
    """Get FlextLdapOperations instance for testing."""
    return FlextLdapOperations(connection=ldap_connection)


@pytest.fixture
def ldap_client(
    ldap_connection: FlextLdapConnection,
    ldap_parser: FlextLdifParser | None,
) -> FlextLdap:
    """Get configured LDAP client instance for testing with established connection.

    Creates a FlextLdap instance with injected dependencies.
    This enables real integration tests with actual LDAP operations.

    Args:
        ldap_connection: LDAP connection instance
        ldap_parser: LDIF parser (optional)

    Returns:
        FlextLdap: Configured LDAP client instance

    """
    operations = FlextLdapOperations(connection=ldap_connection)
    # FlextLdap expects FlextLdif, not FlextLdifParser
    # The parser was already used to create the connection, so we use get_instance()
    return FlextLdap(
        connection=ldap_connection,
        operations=operations,
        ldif=FlextLdif.get_instance(),
    )


# =============================================================================
# HELPER FUNCTIONS FOR TEST CREATION
# =============================================================================


def create_flext_ldap_instance(
    config: FlextLdapConfig | None = None,
    parser: FlextLdifParser | None = None,
) -> FlextLdap:
    """Create a FlextLdap instance for testing without connection.

    Helper function to create FlextLdap instances in tests that don't use fixtures.
    The instance will not be connected - call connect() separately if needed.

    Args:
        config: Optional LDAP configuration (defaults to FlextLdapConfig())
        parser: Optional LDIF parser

    Returns:
        FlextLdap: Unconnected FlextLdap instance

    """
    if config is None:
        config = FlextLdapConfig()
    connection = FlextLdapConnection(config=config, parser=parser)
    operations = FlextLdapOperations(connection=connection)
    # FlextLdap expects FlextLdif, not FlextLdifParser
    # The parser was already used to create the connection, so we use get_instance()
    return FlextLdap(
        connection=connection, operations=operations, ldif=FlextLdif.get_instance()
    )


# @pytest.fixture
# def ldap3_adapter(ldap_parser: FlextLdifParser) -> Ldap3Adapter:
#     """Get Ldap3Adapter instance for testing."""
#     return Ldap3Adapter(parser=ldap_parser)


# @pytest.fixture
# def flext_ldap_instance(
#     ldap_config: FlextLdapConfig,
#     ldap_parser: FlextLdifParser,
# ) -> FlextLdap:
#     """Get FlextLdap instance without connection."""
#     return FlextLdap(config=ldap_config, parser=ldap_parser)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def _ensure_basic_ldap_structure() -> None:
    """Ensure basic LDAP structure exists for tests.

    Creates ou=people, ou=groups, ou=services if they don't exist.
    This is called after container is ready to guarantee test environment.
    """
    try:
        server = Server(f"ldap://localhost:{LDAP_PORT}", get_info="NO_INFO")
        conn = Connection(
            server,
            user=LDAP_ADMIN_DN,
            password=LDAP_ADMIN_PASSWORD,
            auto_bind=True,
        )

        # Check if ou=people exists
        conn.search(LDAP_BASE_DN, "(ou=people)", attributes=["ou"])
        if not conn.entries:
            # Create ou=people
            _ldap3_add(
                conn,
                f"ou=people,{LDAP_BASE_DN}",
                ["organizationalUnit", "top"],
                {
                    "ou": ["people"],
                    "description": ["Organizational unit for people entries"],
                },
            )
            logger.debug("Created ou=people")

        # Check if ou=groups exists
        conn.search(LDAP_BASE_DN, "(ou=groups)", attributes=["ou"])
        if not conn.entries:
            # Create ou=groups
            _ldap3_add(
                conn,
                f"ou=groups,{LDAP_BASE_DN}",
                ["organizationalUnit", "top"],
                {
                    "ou": ["groups"],
                    "description": ["Organizational unit for group entries"],
                },
            )
            logger.debug("Created ou=groups")

        # Check if ou=services exists
        conn.search(LDAP_BASE_DN, "(ou=services)", attributes=["ou"])
        if not conn.entries:
            # Create ou=services
            _ldap3_add(
                conn,
                f"ou=services,{LDAP_BASE_DN}",
                ["organizationalUnit", "top"],
                {
                    "ou": ["services"],
                    "description": ["Organizational unit for service entries"],
                },
            )
            logger.debug("Created ou=services")

        _ldap3_unbind(conn)
        logger.info("Basic LDAP structure verified/created")

    except Exception as e:
        logger.warning("Failed to ensure basic LDAP structure", error=e)
        # Don't fail tests for this - just log warning

from __future__ import annotations

import time
from collections.abc import Callable, Generator
from pathlib import Path

import pytest
from flext_core import FlextLogger
from flext_ldif import FlextLdif, FlextLdifParser

from flext_ldap import (
    FlextLdap,
    FlextLdapConnection,
    FlextLdapOperations,
    FlextLdapSettings,
)
from flext_ldap.adapters.ldap3 import FlextLdapLdap3Wrappers
from ldap3 import Connection, Server
from tests import c, m, u

logger = FlextLogger(__name__)

# Runtime type aliases (PEP 695 TypeAliasType can't be used in r[...]/TypeAdapter at runtime)
GenericFieldsDict = dict[str, str | int | bool | list[str] | dict[str, list[str]]]
LdapContainerDict = dict[str, str | int | bool]


SAMPLE_USER_ENTRY = c.Ldap.Tests.SampleData.USER_ENTRY
SAMPLE_GROUP_ENTRY = c.Ldap.Tests.SampleData.GROUP_ENTRY
FLEXT_LDAP_ROOT = Path(__file__).parent.parent.resolve()
FLEXT_WORKSPACE_ROOT = FLEXT_LDAP_ROOT.parent

_docker = c.Ldap.Tests.Docker
LDAP_CONTAINER_NAME = _docker.CONTAINER_NAME
LDAP_COMPOSE_FILE = FLEXT_WORKSPACE_ROOT / _docker.COMPOSE_FILE_REL
LDAP_SERVICE_NAME = _docker.SERVICE_NAME
LDAP_PORT = _docker.PORT
LDAP_BASE_DN = _docker.BASE_DN
LDAP_ADMIN_DN = _docker.ADMIN_DN
LDAP_ADMIN_PASSWORD = _docker.ADMIN_PASSWORD
LDAP_LEGACY_ADMIN_DN = _docker.LEGACY_ADMIN_DN
LDAP_LEGACY_ADMIN_PASSWORD = _docker.LEGACY_ADMIN_PASSWORD


def pytest_sessionstart(session: pytest.Session) -> None:
    if session.config.option.collectonly:
        logger.info("Test collection mode - skipping Docker initialization")
        return
    worker_input_val = getattr(session.config, "workerinput", None)
    worker_input: dict[str, object] = (
        worker_input_val if isinstance(worker_input_val, dict) else {}
    )
    worker_id = str(worker_input.get("workerid", "master"))
    docker_control = u.Ldap.Tests.get_docker_control(worker_id)
    is_dirty = docker_control.is_container_dirty(LDAP_CONTAINER_NAME)
    if is_dirty:
        logger.info(
            "Container %s is dirty, recreating with fresh volumes", LDAP_CONTAINER_NAME
        )
        compose_file_rel = str(LDAP_COMPOSE_FILE.relative_to(FLEXT_WORKSPACE_ROOT))
        compose_result = docker_control.compose_down(compose_file_rel)
        if compose_result.is_failure:
            logger.warning(f"Compose down failed: {compose_result.error}")
        create_result = docker_control.compose_up(
            compose_file_rel, service=LDAP_SERVICE_NAME, force_recreate=True
        )
        if create_result.is_failure:
            logger.warning(f"Container recreate failed: {create_result.error}")
        else:
            docker_control.mark_container_clean(LDAP_CONTAINER_NAME)
            logger.info("Recreated dirty container: %s", LDAP_CONTAINER_NAME)
    else:
        start_result = docker_control.start_existing_container(LDAP_CONTAINER_NAME)
        if start_result.is_success:
            logger.info(f"Container {LDAP_CONTAINER_NAME}: {start_result.value}")
        else:
            logger.info(
                "Container %s not found, creating with compose...", LDAP_CONTAINER_NAME
            )
            compose_file_rel = str(LDAP_COMPOSE_FILE.relative_to(FLEXT_WORKSPACE_ROOT))
            create_result = docker_control.compose_up(
                compose_file_rel, service=LDAP_SERVICE_NAME
            )
            if create_result.is_failure:
                logger.warning(f"Container create failed: {create_result.error}")
            else:
                logger.info("Container %s created", LDAP_CONTAINER_NAME)
    container_name = LDAP_CONTAINER_NAME
    port_ready_result = docker_control.wait_for_port_ready("localhost", LDAP_PORT, 90)
    if port_ready_result.is_success and port_ready_result.value:
        admin_dn, admin_password = u.Ldap.Tests.get_admin_credentials()
        ldap_ready = False
        waited = 0.0
        wait_interval = 1.0
        while waited < 90:
            try:
                server = Server(f"ldap://localhost:{LDAP_PORT}", get_info="NO_INFO")
                test_conn = Connection(
                    server,
                    user=admin_dn,
                    password=admin_password,
                    auto_bind=True,
                    receive_timeout=1,
                )
                if test_conn.bound:
                    FlextLdapLdap3Wrappers.unbind(test_conn)
                    ldap_ready = True
                    break
            except Exception:
                pass
            time.sleep(wait_interval)
            waited += wait_interval
        if ldap_ready:
            logger.info(
                "Container %s bind-ready after %.1fs in session start",
                container_name,
                waited,
            )
        else:
            logger.warning(
                "Container %s port is open but LDAP bind is not ready yet",
                container_name,
            )


def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]) -> None:
    if call.excinfo is None:
        return
    exc_type = call.excinfo.type
    exc_msg = str(call.excinfo.value).lower()
    exc_type_str = str(exc_type).lower()
    infrastructure_errors = [
        "ldapsessionterminatedbyservererror",
        "ldapserverdownerror",
        "ldap server is not responding",
        "broken pipe",
        "session terminated by server",
        "ldapoperationresult",
    ]
    transient_errors = [
        "connection refused",
        "connection reset by peer",
        "cannot connect to ldap",
        "ldapsocketopenerror",
        "ldapcommunicationerror",
        "ldap bind failed",
        "timeout",
    ]
    is_infrastructure_failure = any(
        err in exc_type_str or err in exc_msg for err in infrastructure_errors
    )
    is_transient = any(
        err in exc_type_str or err in exc_msg for err in transient_errors
    )
    if is_infrastructure_failure and (not is_transient):
        worker_input_val = getattr(item.session.config, "workerinput", None)
        worker_input: dict[str, object] = (
            worker_input_val if isinstance(worker_input_val, dict) else {}
        )
        worker_id = str(worker_input.get("workerid", "master"))
        docker = u.Ldap.Tests.get_docker_control(worker_id)
        docker.mark_container_dirty(LDAP_CONTAINER_NAME)
        logger.error(
            f"LDAP INFRASTRUCTURE FAILURE in {item.nodeid}, container marked DIRTY for recreation on next session: {exc_msg}"
        )
    elif is_transient:
        logger.warning(
            f"LDAP transient error in {item.nodeid} (not marking dirty): {exc_msg}"
        )


@pytest.fixture(scope="session")
def worker_id(request: pytest.FixtureRequest) -> str:
    worker_input_val = getattr(request.config, "workerinput", None)
    worker_input: dict[str, object] = (
        worker_input_val if isinstance(worker_input_val, dict) else {}
    )
    worker_id = worker_input.get("workerid", "master")
    return str(worker_id)


@pytest.fixture(scope="session")
def session_id() -> str:
    return str(int(time.time() * 1000))


@pytest.fixture(scope="session")
def test_dns_tracker() -> u.Ldap.Tests.DNSTracker:
    return u.Ldap.Tests.DNSTracker()


@pytest.fixture
def unique_dn_suffix(
    worker_id: str, session_id: str, request: pytest.FixtureRequest
) -> str:
    test_name = request.node.name if hasattr(request, "node") else "unknown"
    allowed_chars = {"-", "_"}
    test_name_clean = "".join(
        c if c.isalnum() or c in allowed_chars else "-" for c in test_name
    )[:20]
    test_id = int(time.time() * 1000000) % 1000000
    return f"{worker_id}-{session_id}-{test_name_clean}-{test_id}"


@pytest.fixture
def make_user_dn(
    unique_dn_suffix: str, ldap_container: LdapContainerDict
) -> Callable[[str], str]:
    base_dn = str(ldap_container.get("base_dn", "dc=flext,dc=local"))

    def _make(uid: str) -> str:
        return f"uid={uid}-{unique_dn_suffix},ou=people,{base_dn}"

    return _make


@pytest.fixture
def make_group_dn(
    unique_dn_suffix: str, ldap_container: LdapContainerDict
) -> Callable[[str], str]:
    base_dn = str(ldap_container.get("base_dn", "dc=flext,dc=local"))

    def _make(cn: str) -> str:
        return f"cn={cn}-{unique_dn_suffix},ou=groups,{base_dn}"

    return _make


@pytest.fixture(scope="session")
def ldap_container(worker_id: str) -> LdapContainerDict:
    lock_file = Path.home() / ".flext" / f"{LDAP_CONTAINER_NAME}.lock"
    lock = u.Ldap.Tests.FileLock(lock_file)
    docker_control = u.Ldap.Tests.get_docker_control(worker_id)
    with lock:
        max_wait: int = 60
        wait_interval: float = 1.0
        admin_dn, admin_password = u.Ldap.Tests.get_admin_credentials()
        logger.info("Waiting for container %s to be ready...", LDAP_CONTAINER_NAME)
        port_result = docker_control.wait_for_port_ready(
            "localhost", LDAP_PORT, max_wait
        )
        if port_result.is_failure or not port_result.value:
            pytest.fail(
                f"Container {LDAP_CONTAINER_NAME} port {LDAP_PORT} not ready within {max_wait}s: {port_result.error or 'timeout'}. This test requires a running LDAP container."
            )
        waited: float = 0.0
        ldap_ready = False
        while waited < max_wait:
            try:
                server = Server(f"ldap://localhost:{LDAP_PORT}", get_info="NO_INFO")
                test_conn = Connection(
                    server,
                    user=admin_dn,
                    password=admin_password,
                    auto_bind=True,
                    receive_timeout=1,
                )
                if test_conn.bound:
                    FlextLdapLdap3Wrappers.unbind(test_conn)
                    logger.info(
                        f"Container {LDAP_CONTAINER_NAME} is ready after {waited:.1f}s"
                    )
                    ldap_ready = True
                    break
            except Exception as e:
                if waited % 10 == 0:
                    logger.debug(
                        f"Container {LDAP_CONTAINER_NAME} not ready yet (waited {waited:.1f}s): {e}"
                    )
            time.sleep(wait_interval)
            waited += wait_interval
        if not ldap_ready:
            pytest.fail(
                f"Container {LDAP_CONTAINER_NAME} LDAP service not ready within {max_wait}s. This test requires a running and responsive LDAP container."
            )
    with lock:
        u.Ldap.Tests.ensure_basic_ldap_structure()
    container_info: LdapContainerDict = {
        "server_url": f"ldap://localhost:{LDAP_PORT}",
        "host": "localhost",
        "bind_dn": admin_dn,
        "password": admin_password,
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
    return container_info


@pytest.fixture(scope="module")
def ldap_parser() -> FlextLdifParser:
    ldif = FlextLdif()
    return ldif.parser


@pytest.fixture
def sample_connection_config() -> m.Ldap.ConnectionConfig:
    return m.Ldap.ConnectionConfig(
        host="localhost",
        port=3390,
        use_ssl=False,
        bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=test,dc=local",
        bind_password="test123",
    )


@pytest.fixture(scope="module")
def ldap_config(ldap_container: LdapContainerDict) -> FlextLdapSettings:
    port_value = ldap_container["port"]
    port_int = int(port_value) if isinstance(port_value, (int, str)) else 3390
    return FlextLdapSettings(
        host=str(ldap_container["host"]),
        port=port_int,
        use_ssl=False,
        bind_dn=str(ldap_container["bind_dn"]),
        bind_password=str(ldap_container["password"]),
    )


@pytest.fixture(scope="module")
def connection_config(ldap_container: LdapContainerDict) -> m.Ldap.ConnectionConfig:
    port_value = ldap_container["port"]
    port_int = int(port_value) if isinstance(port_value, (int, str)) else 3390
    return m.Ldap.ConnectionConfig(
        host=str(ldap_container["host"]),
        port=port_int,
        use_ssl=False,
        bind_dn=str(ldap_container["bind_dn"]),
        bind_password=str(ldap_container["password"]),
    )


@pytest.fixture
def search_options(ldap_container: LdapContainerDict) -> m.Ldap.SearchOptions:
    base_dn = str(ldap_container.get("base_dn", "dc=example,dc=com"))
    return m.Ldap.SearchOptions(
        base_dn=base_dn, filter_str="(objectClass=*)", scope=c.Ldap.SearchScope.SUBTREE
    )


@pytest.fixture(scope="session")
def ldap_test_data_loader(
    ldap_container: LdapContainerDict,
    test_dns_tracker: u.Ldap.Tests.DNSTracker,
) -> Generator[Connection]:
    try:
        server = Server(f"ldap://localhost:{LDAP_PORT}", get_info="ALL")
        connection = Connection(
            server,
            user=str(ldap_container["bind_dn"]),
            password=str(ldap_container["password"]),
            auto_bind=True,
            auto_referrals=False,
        )
        ous = [
            (f"ou=people,{LDAP_BASE_DN}", "people"),
            (f"ou=groups,{LDAP_BASE_DN}", "groups"),
            (f"ou=system,{LDAP_BASE_DN}", "system"),
        ]
        for ou_dn, ou_name in ous:
            try:
                _ = FlextLdapLdap3Wrappers.add(
                    connection,
                    ou_dn,
                    object_class=["organizationalUnit", "top"],
                    attributes={
                        "ou": [ou_name],
                    },
                )
            except Exception:
                pass
        yield connection
        try:
            all_dns = test_dns_tracker.get_all()
            logger.info(f"Cleaning up {len(all_dns)} tracked DNs from tests")
            for dn in all_dns:
                try:
                    _ = FlextLdapLdap3Wrappers.delete(connection, dn)
                    logger.debug("Cleaned up DN: %s", dn)
                except Exception as e:
                    error_repr = str(e)
                    logger.debug("Cleanup skip for %s: %s", dn, error_repr)
        except Exception as e:
            logger.warning("Cleanup failed (non-critical)", error=e)
        if connection.bound:
            FlextLdapLdap3Wrappers.unbind(connection)
    except Exception as e:
        logger.exception("Failed to initialize test data loader")
        pytest.fail(
            f"Test data loader initialization failed: {e!s}. This test requires a working LDAP container and connection."
        )


@pytest.fixture
def test_users_json() -> list[GenericFieldsDict]:
    return u.Ldap.Tests.Fixtures.load_users_json()


@pytest.fixture
def test_groups_json() -> list[GenericFieldsDict]:
    return u.Ldap.Tests.Fixtures.load_groups_json()


@pytest.fixture
def base_ldif_content() -> str:
    return u.Ldap.Tests.Fixtures.load_base_ldif()


@pytest.fixture
def base_ldif_entries() -> list[m.Ldif.Entry]:
    return u.Ldap.Tests.Fixtures.load_base_ldif_entries()


@pytest.fixture
def test_user_entry(test_users_json: list[GenericFieldsDict]) -> GenericFieldsDict:
    if not test_users_json:
        default_user: GenericFieldsDict = {
            "dn": "uid=testuser,ou=people,dc=flext,dc=local",
            "attributes": {
                "objectClass": ["top", "person", "inetOrgPerson"],
                "uid": ["testuser"],
                "cn": ["Test User"],
                "sn": ["User"],
            },
        }
        return default_user
    return u.Ldap.Tests.Fixtures.convert_user_json_to_entry(test_users_json[0])


@pytest.fixture
def test_group_entry(test_groups_json: list[GenericFieldsDict]) -> GenericFieldsDict:
    if not test_groups_json:
        default_group: GenericFieldsDict = {
            "dn": "cn=testgroup,ou=groups,dc=flext,dc=local",
            "attributes": {
                "objectClass": ["top", "groupOfNames"],
                "cn": ["testgroup"],
                "member": ["uid=testuser,ou=people,dc=flext,dc=local"],
            },
        }
        return default_group
    return u.Ldap.Tests.Fixtures.convert_group_json_to_entry(test_groups_json[0])


@pytest.fixture
def ldap_connection(
    ldap_config: FlextLdapSettings,
    ldap_parser: FlextLdifParser | None,
    ldap_container: LdapContainerDict,
) -> Generator[FlextLdapConnection]:
    connection = FlextLdapConnection(config=ldap_config, parser=ldap_parser)
    try:
        connection_config = m.Ldap.ConnectionConfig(
            host=ldap_config.host,
            port=ldap_config.port,
            use_ssl=ldap_config.use_ssl,
            bind_dn=ldap_config.bind_dn,
            bind_password=ldap_config.bind_password,
        )
        connect_result = connection.connect(connection_config)
        if connect_result.is_failure:
            logger.error(f"Failed to connect to LDAP: {connect_result.error}")
            pytest.fail(
                f"LDAP connection failed: {connect_result.error}. This test requires a running LDAP container."
            )
        yield connection
    except Exception as e:
        logger.exception("Error in ldap_connection fixture")
        pytest.fail(
            f"LDAP connection fixture error: {e}. This test requires a working LDAP container and connection."
        )
    finally:
        try:
            connection.disconnect()
        except Exception as cleanup_error:
            logger.warning("Error during LDAP disconnect", error=cleanup_error)


@pytest.fixture
def ldap3_connection(ldap_container: LdapContainerDict) -> Generator[Connection]:
    server = Server(
        f"ldap://{ldap_container['host']}:{ldap_container['port']}", get_info="ALL"
    )
    connection = Connection(
        server,
        user=str(ldap_container["bind_dn"]),
        password=str(ldap_container["password"]),
        auto_bind=True,
    )
    yield connection
    if getattr(connection, "bound", False):
        connection.unbind()


@pytest.fixture
def ldap_operations(ldap_connection: FlextLdapConnection) -> FlextLdapOperations:
    return FlextLdapOperations(connection=ldap_connection)


@pytest.fixture
def ldap_client(
    ldap_connection: FlextLdapConnection, ldap_parser: FlextLdifParser | None
) -> FlextLdap:
    operations = FlextLdapOperations(connection=ldap_connection)
    return FlextLdap(
        connection=ldap_connection, operations=operations, ldif=FlextLdif()
    )

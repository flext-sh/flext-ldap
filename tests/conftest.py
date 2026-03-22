from __future__ import annotations

import socket
import time
from pathlib import Path

import pytest
from flext_core import FlextLogger, r

from flext_ldap.adapters.ldap3 import FlextLdapLdap3Wrappers
from ldap3 import Connection, Server
from ldap3.core.exceptions import LDAPException
from tests.constants import TestsFlextLdapConstants as c
from tests.models import TestsFlextLdapModels as m
from tests.utilities import TestsFlextLdapUtilities as u

logger = FlextLogger(__name__)

LdapContainerDict = dict[str, str | int | bool]


def _get_worker_id(config: pytest.Config) -> str:
    worker_input_val = getattr(config, "workerinput", None)
    worker_input: dict[str, str | int | bool] = (
        worker_input_val if isinstance(worker_input_val, dict) else {}
    )
    return str(worker_input.get("workerid", "master"))


def _wait_for_port_ready(host: str, port: int, timeout: int) -> r[bool]:
    """Wait until a TCP port is accepting connections."""
    waited = 0.0
    while waited < timeout:
        try:
            with socket.create_connection((host, port), timeout=1):
                return r[bool].ok(value=True)
        except (ConnectionRefusedError, TimeoutError, OSError):
            time.sleep(1.0)
            waited += 1.0
    return r[bool].fail(f"Port {port} not ready after {timeout}s")


def pytest_sessionstart(session: pytest.Session) -> None:
    if session.config.option.collectonly:
        return
    worker_id = _get_worker_id(session.config)
    docker_control = u.Ldap.Tests.get_docker_control(worker_id)
    compose_file_rel = str(
        (
            Path(__file__).parent.parent.parent.resolve()
            / c.Ldap.Tests.Docker.COMPOSE_FILE_REL
        ).relative_to(Path(__file__).parent.parent.parent.resolve())
    )
    if docker_control.is_container_dirty(c.Ldap.Tests.Docker.CONTAINER_NAME):
        logger.info(
            "Container %s is dirty, recreating", c.Ldap.Tests.Docker.CONTAINER_NAME
        )
        docker_control.compose_down(compose_file_rel)
        result = docker_control.compose_up(
            compose_file_rel,
            service=c.Ldap.Tests.Docker.SERVICE_NAME,
            force_recreate=True,
        )
        if result.is_success:
            docker_control.mark_container_clean(c.Ldap.Tests.Docker.CONTAINER_NAME)
    else:
        start = docker_control.start_existing_container(
            c.Ldap.Tests.Docker.CONTAINER_NAME
        )
        if start.is_failure:
            docker_control.compose_up(
                compose_file_rel, service=c.Ldap.Tests.Docker.SERVICE_NAME
            )
    port_ready = _wait_for_port_ready("localhost", c.Ldap.Tests.Docker.PORT, 90)
    if port_ready.is_success and port_ready.value:
        admin_dn, admin_password = u.Ldap.Tests.get_admin_credentials()
        waited = 0.0
        while waited < 90:
            try:
                srv = Server(
                    f"ldap://localhost:{c.Ldap.Tests.Docker.PORT}", get_info="NO_INFO"
                )
                conn = Connection(
                    srv,
                    user=admin_dn,
                    password=admin_password,
                    auto_bind=True,
                    receive_timeout=1,
                )
                if conn.bound:
                    FlextLdapLdap3Wrappers.unbind(conn)
                    logger.info(
                        "Container %s bind-ready after %.1fs",
                        c.Ldap.Tests.Docker.CONTAINER_NAME,
                        waited,
                    )
                    break
            except (LDAPException, ConnectionError, TimeoutError, OSError):
                pass
            time.sleep(1.0)
            waited += 1.0


_INFRASTRUCTURE_ERRORS = frozenset({
    "ldapsessionterminatedbyservererror",
    "ldapserverdownerror",
    "ldap server is not responding",
    "broken pipe",
    "session terminated by server",
    "ldapoperationresult",
})
_TRANSIENT_ERRORS = frozenset({
    "connection refused",
    "connection reset by peer",
    "cannot connect to ldap",
    "ldapsocketopenerror",
    "ldapcommunicationerror",
    "ldap bind failed",
    "timeout",
})


def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]) -> None:
    if call.excinfo is None:
        return
    exc_msg = str(call.excinfo.value).lower()
    exc_type_str = str(call.excinfo.type).lower()
    combined = exc_type_str + " " + exc_msg
    is_infra = any(e in combined for e in _INFRASTRUCTURE_ERRORS)
    is_transient = any(e in combined for e in _TRANSIENT_ERRORS)
    if is_infra and not is_transient:
        worker_id = _get_worker_id(item.session.config)
        docker = u.Ldap.Tests.get_docker_control(worker_id)
        docker.mark_container_dirty(c.Ldap.Tests.Docker.CONTAINER_NAME)
        logger.error(
            "LDAP INFRASTRUCTURE FAILURE in %s, container marked DIRTY: %s",
            item.nodeid,
            exc_msg,
        )


@pytest.fixture(scope="session")
def worker_id(request: pytest.FixtureRequest) -> str:
    return _get_worker_id(request.config)


@pytest.fixture(scope="session")
def ldap_container(worker_id: str) -> LdapContainerDict:
    lock = u.Ldap.Tests.FileLock(
        Path.home() / ".flext" / f"{c.Ldap.Tests.Docker.CONTAINER_NAME}.lock"
    )
    u.Ldap.Tests.get_docker_control(worker_id)
    with lock:
        admin_dn, admin_password = u.Ldap.Tests.get_admin_credentials()
        port_result = _wait_for_port_ready("localhost", c.Ldap.Tests.Docker.PORT, 60)
        if port_result.is_failure or not port_result.value:
            pytest.fail(
                f"Container {c.Ldap.Tests.Docker.CONTAINER_NAME} port {c.Ldap.Tests.Docker.PORT} not ready within 60s"
            )
        waited: float = 0.0
        while waited < 60:
            try:
                srv = Server(
                    f"ldap://localhost:{c.Ldap.Tests.Docker.PORT}", get_info="NO_INFO"
                )
                conn = Connection(
                    srv,
                    user=admin_dn,
                    password=admin_password,
                    auto_bind=True,
                    receive_timeout=1,
                )
                if conn.bound:
                    FlextLdapLdap3Wrappers.unbind(conn)
                    break
            except (LDAPException, ConnectionError, TimeoutError, OSError):
                pass
            time.sleep(1.0)
            waited += 1.0
        else:
            pytest.fail(
                f"Container {c.Ldap.Tests.Docker.CONTAINER_NAME} LDAP not ready within 60s"
            )
    with lock:
        u.Ldap.Tests.ensure_basic_ldap_structure()
    return {
        "server_url": f"ldap://localhost:{c.Ldap.Tests.Docker.PORT}",
        "host": "localhost",
        "bind_dn": admin_dn,
        "password": admin_password,
        "base_dn": c.Ldap.Tests.Docker.BASE_DN,
        "port": c.Ldap.Tests.Docker.PORT,
        "use_ssl": False,
        "worker_id": worker_id,
    }


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
        base_dn=base_dn,
        filter_str="(objectClass=*)",
        scope=c.Ldap.SearchScope.SUBTREE,
    )

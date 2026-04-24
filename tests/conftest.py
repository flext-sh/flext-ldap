from __future__ import annotations

import socket
import time
from collections.abc import (
    Callable,
    Mapping,
)
from pathlib import Path
from typing import Protocol, TypeGuard

import pytest
from flext_core import FlextSettings

from flext_ldap import FlextLdapLdap3Wrappers, FlextLdapSettings
from tests import c, m, p, r, t, u

logger = u.fetch_logger(__name__)


@pytest.fixture(autouse=True)
def reset_settings_singleton() -> None:
    """Reset FlextSettings singleton between tests."""
    FlextSettings.reset_for_testing()


@pytest.fixture
def ldap_settings(
    settings_factory: Callable[..., FlextLdapSettings],
) -> FlextLdapSettings:
    """Provide clean FlextLdapSettings for tests."""
    return settings_factory(FlextLdapSettings)


class WorkerInputConfig(Protocol):
    workerinput: t.StrMapping


def _has_workerinput(settings: pytest.Config) -> TypeGuard[WorkerInputConfig]:
    workerinput = getattr(settings, "workerinput", None)
    return isinstance(workerinput, Mapping)


def _get_worker_id(settings: pytest.Config) -> str:
    if not _has_workerinput(settings):
        return c.Ldap.Tests.DOCKER_DEFAULT_WORKER_ID
    worker_id_obj = settings.workerinput.get(
        "workerid",
        c.Ldap.Tests.DOCKER_DEFAULT_WORKER_ID,
    )
    return str(worker_id_obj)


def _wait_for_port_ready(host: str, port: int, timeout: int) -> p.Result[bool]:
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
            / c.Ldap.Tests.DOCKER_COMPOSE_FILE_REL
        ).relative_to(Path(__file__).parent.parent.parent.resolve()),
    )
    if docker_control.container_dirty(c.Ldap.Tests.DOCKER_CONTAINER_NAME):
        logger.info(
            "Container %s is dirty, recreating",
            c.Ldap.Tests.DOCKER_CONTAINER_NAME,
        )
        docker_control.compose_down(compose_file_rel)
        result = docker_control.compose_up(
            compose_file_rel,
            service=c.Ldap.Tests.DOCKER_SERVICE_NAME,
            force_recreate=True,
        )
        if result.success:
            docker_control.mark_container_clean(c.Ldap.Tests.DOCKER_CONTAINER_NAME)
    else:
        start = docker_control.start_existing_container(
            c.Ldap.Tests.DOCKER_CONTAINER_NAME,
        )
        if start.failure:
            docker_control.compose_up(
                compose_file_rel,
                service=c.Ldap.Tests.DOCKER_SERVICE_NAME,
            )
    port_ready = _wait_for_port_ready(
        c.LOCALHOST,
        c.Ldap.Tests.DOCKER_PORT,
        c.Ldap.Tests.DOCKER_STARTUP_TIMEOUT,
    )
    if port_ready.success and port_ready.value:
        admin_dn, admin_password = u.Ldap.Tests.get_admin_credentials()
        waited = 0.0
        while waited < c.Ldap.Tests.DOCKER_STARTUP_TIMEOUT:
            try:
                srv = u.Ldap.create_server_from_url(
                    f"ldap://{c.LOCALHOST}:{c.Ldap.Tests.DOCKER_PORT}",
                    get_info="NO_INFO",
                )
                conn = u.Ldap.create_connection(
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
                        c.Ldap.Tests.DOCKER_CONTAINER_NAME,
                        waited,
                    )
                    break
            except (t.Ldap.LDAPException, ConnectionError, TimeoutError, OSError):
                pass
            time.sleep(1.0)
            waited += 1.0


def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]) -> None:
    if call.excinfo is None:
        return
    exc_msg = str(call.excinfo.value).lower()
    exc_type_str = str(call.excinfo.type).lower()
    combined = exc_type_str + " " + exc_msg
    is_infra = any(e in combined for e in c.Ldap.Tests.ERROR_INFRASTRUCTURE_PATTERNS)
    is_transient = any(e in combined for e in c.Ldap.Tests.ERROR_TRANSIENT_PATTERNS)
    if is_infra and not is_transient:
        worker_id = _get_worker_id(item.session.config)
        docker = u.Ldap.Tests.get_docker_control(worker_id)
        docker.mark_container_dirty(c.Ldap.Tests.DOCKER_CONTAINER_NAME)
        logger.error(
            "LDAP INFRASTRUCTURE FAILURE in %s, container marked DIRTY: %s",
            item.nodeid,
            exc_msg,
        )


@pytest.fixture(scope="session")
def worker_id(request: pytest.FixtureRequest) -> str:
    return _get_worker_id(request.config)


@pytest.fixture(scope="session")
def ldap_container(
    worker_id: str,
) -> t.MappingKV[str, t.Scalar]:
    lock = u.Ldap.Tests.FileLock(
        Path.home() / ".flext" / f"{c.Ldap.Tests.DOCKER_CONTAINER_NAME}.lock",
    )
    u.Ldap.Tests.get_docker_control(worker_id)
    with lock:
        admin_dn, admin_password = u.Ldap.Tests.get_admin_credentials()
        port_result = _wait_for_port_ready(
            c.LOCALHOST,
            c.Ldap.Tests.DOCKER_PORT,
            c.Ldap.Tests.DOCKER_BIND_READY_TIMEOUT,
        )
        if port_result.failure or not port_result.value:
            pytest.fail(
                f"Container {c.Ldap.Tests.DOCKER_CONTAINER_NAME} port {c.Ldap.Tests.DOCKER_PORT} not ready within {c.Ldap.Tests.DOCKER_BIND_READY_TIMEOUT}s",
            )
        waited: float = 0.0
        while waited < c.Ldap.Tests.DOCKER_BIND_READY_TIMEOUT:
            try:
                srv = u.Ldap.create_server_from_url(
                    f"ldap://{c.LOCALHOST}:{c.Ldap.Tests.DOCKER_PORT}",
                    get_info="NO_INFO",
                )
                conn = u.Ldap.create_connection(
                    srv,
                    user=admin_dn,
                    password=admin_password,
                    auto_bind=True,
                    receive_timeout=1,
                )
                if conn.bound:
                    FlextLdapLdap3Wrappers.unbind(conn)
                    break
            except (t.Ldap.LDAPException, ConnectionError, TimeoutError, OSError):
                pass
            time.sleep(1.0)
            waited += 1.0
        else:
            pytest.fail(
                f"Container {c.Ldap.Tests.DOCKER_CONTAINER_NAME} LDAP not ready within {c.Ldap.Tests.DOCKER_BIND_READY_TIMEOUT}s",
            )
    with lock:
        u.Ldap.Tests.ensure_basic_ldap_structure()
    return {
        "server_url": f"ldap://{c.LOCALHOST}:{c.Ldap.Tests.DOCKER_PORT}",
        "host": c.LOCALHOST,
        "bind_dn": admin_dn,
        "password": admin_password,
        "base_dn": c.Ldap.Tests.DOCKER_BASE_DN,
        "port": c.Ldap.Tests.DOCKER_PORT,
        "use_ssl": False,
        "worker_id": worker_id,
    }


@pytest.fixture(scope="module")
def connection_config(
    ldap_container: t.MappingKV[str, t.Scalar],
) -> m.Ldap.ConnectionConfig:
    port_value = ldap_container["port"]
    port_int = (
        int(port_value)
        if isinstance(port_value, (int, str))
        else c.Ldap.Tests.DOCKER_PORT
    )
    return m.Ldap.ConnectionConfig(
        host=str(ldap_container["host"]),
        port=port_int,
        use_ssl=False,
        bind_dn=str(ldap_container["bind_dn"]),
        bind_password=str(ldap_container["password"]),
    )


@pytest.fixture
def search_options(
    ldap_container: t.MappingKV[str, t.Scalar],
) -> m.Ldap.SearchOptions:
    base_dn = str(ldap_container.get("base_dn", c.Ldap.Defaults.EXAMPLE_BASE_DN))
    return m.Ldap.SearchOptions(
        base_dn=base_dn,
        filter_str=c.Ldap.Filters.ALL_ENTRIES_FILTER,
        scope=c.Ldap.SearchScope.SUBTREE,
    )

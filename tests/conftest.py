"""Conftests for flext-ldap.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

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
from tests import c, m, t, u

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
    return settings.workerinput.get(
        "workerid",
        c.Ldap.Tests.DOCKER_DEFAULT_WORKER_ID,
    )


def _docker_compose_path() -> Path:
    return Path(__file__).resolve().parents[1] / c.Ldap.Tests.DOCKER_COMPOSE_FILE_REL


def _docker_compose_available() -> bool:
    return _docker_compose_path().exists()


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
    if not _docker_compose_available():
        pytest.fail(
            "LDAP smoke tests require the Docker compose file and cannot "
            "run without it.",
        )
    lock = u.Ldap.Tests.FileLock(
        Path.home() / ".flext" / f"{c.Ldap.Tests.DOCKER_CONTAINER_NAME}.lock",
    )
    docker_control = u.Ldap.Tests.get_docker_control(worker_id)
    with lock:
        admin_dn, admin_password = u.Ldap.Tests.get_admin_credentials()
        execute_result = docker_control.execute()
        if execute_result.failure:
            msg = (
                f"Container {c.Ldap.Tests.DOCKER_CONTAINER_NAME} startup "
                f"failed: {execute_result.error}"
            )
            pytest.fail(msg)
        waited: float = 0.0
        while waited < c.Ldap.Tests.DOCKER_BIND_READY_TIMEOUT:
            try:
                srv = u.Ldap.create_server_from_url(
                    f"ldap://{c.LOCALHOST}:{c.Ldap.Tests.DOCKER_PORT}",
                    get_info=c.Ldap.Ldap3GetInfo.NO_INFO,
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
            msg = (
                f"Container {c.Ldap.Tests.DOCKER_CONTAINER_NAME} LDAP not ready "
                f"within {c.Ldap.Tests.DOCKER_BIND_READY_TIMEOUT}s"
            )
            pytest.fail(msg)
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
    if isinstance(port_value, int):
        port_int = port_value
    elif isinstance(port_value, str):
        port_int = int(port_value)
    else:
        raise TypeError(
            f"ldap_container port must be int or str, got {type(port_value).__name__}",
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
    base_dn = str(ldap_container.get("base_dn", c.Ldap.EXAMPLE_BASE_DN))
    return m.Ldap.SearchOptions(
        base_dn=base_dn,
        filter_str=c.Ldap.ALL_ENTRIES_FILTER,
        scope=c.Ldap.SearchScope.SUBTREE,
    )

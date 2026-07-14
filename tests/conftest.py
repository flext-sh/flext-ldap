"""Conftests for flext-ldap.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol, TypeGuard

import pytest

from flext_ldap.adapters._ldap3.wrappers import FlextLdapLdap3Wrappers
from tests import c, t, u

# NOTE (multi-agent): mro-wkii.17.20 relies on the flext_tests pytest11 fixtures.
logger = u.fetch_logger(__name__)


class WorkerInputConfig(Protocol):
    workerinput: t.StrMapping


def _has_workerinput(settings: pytest.Config) -> TypeGuard[WorkerInputConfig]:
    workerinput = getattr(settings, "workerinput", None)
    return isinstance(workerinput, Mapping)


def _get_worker_id(settings: pytest.Config) -> str:
    default_worker_id: str = c.Ldap.Tests.DOCKER_DEFAULT_WORKER_ID
    if not _has_workerinput(settings):
        return default_worker_id
    worker_id: str = settings.workerinput.get(
        "workerid",
        default_worker_id,
    )
    return worker_id


def _docker_compose_path() -> Path:
    compose_file_rel: str = c.Ldap.Tests.DOCKER_COMPOSE_FILE_REL
    return Path(__file__).resolve().parents[1] / compose_file_rel


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
        pytest.skip(
            "LDAP smoke tests require the Docker compose file; skipping because "
            "it is unavailable in this environment.",
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
                f"failed (LDAP server unavailable): {execute_result.error}"
            )
            pytest.skip(msg)
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
                f"within {c.Ldap.Tests.DOCKER_BIND_READY_TIMEOUT}s "
                f"(LDAP server unavailable)"
            )
            pytest.skip(msg)
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

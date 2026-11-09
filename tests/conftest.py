"""Conftests for flext-ldap.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Generator, Mapping

import pytest

from tests import c, t, u


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Select the native shared LDAP service only for its fixture consumers."""
    for item in items:
        if isinstance(item, pytest.Function) and "ldap_container" in item.fixturenames:
            item.add_marker(pytest.mark.ldap)


@pytest.fixture(scope="function")
def ldap_container() -> Generator[Mapping[str, t.Scalar]]:
    """Connect to the selected native service with its own resolved credentials.

    Yields:
        Connection facts with the shared service lease held for this test only.

    """
    docker = u.Ldap.Tests.get_docker_control()
    with docker.lease():
        info = docker.verify().unwrap()
        environment = docker.fetch_container_environment(
            info.name,
            ("LDAP_BASE_DN", "LDAP_ADMIN_PASSWORD"),
        ).unwrap()
        base = environment["LDAP_BASE_DN"].get_secret_value()
        port = u.Tests.resolve_host_port(
            info, c.Ldap.Tests.DOCKER_CONTAINER_PORT
        ).unwrap()
        yield {
            "server_url": f"ldap://{c.LOCALHOST}:{port}",
            "host": c.LOCALHOST,
            "bind_dn": f"cn=admin,{base}",
            "password": environment["LDAP_ADMIN_PASSWORD"].get_secret_value(),
            "base_dn": base,
            "port": port,
            "use_ssl": False,
        }

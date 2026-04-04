"""Docker infrastructure utilities for flext-ldap test setup.

Provides _DockerInfraUtils class composable into FlextLdapUtilities.Ldap.Tests via MRO.
Access: FlextLdapUtilities.Ldap.Tests.FileLock, FlextLdapUtilities.Ldap.Tests.get_docker_control(), etc.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import fcntl
import os
import types
from pathlib import Path
from threading import Lock
from typing import ClassVar, TextIO

from flext_tests import tk

from flext_core import FlextLogger
from flext_ldap import FlextLdapLdap3Wrappers, FlextLdapUtilities
from tests import c


class _DockerInfraUtils:
    """Docker infrastructure helpers composed into FlextLdapUtilities.Ldap.Tests via MRO.

    Provides FileLock, DNSTracker, get_docker_control, get_admin_credentials,
    ensure_basic_ldap_structure — all accessible flat from FlextLdapUtilities.Ldap.Tests.*.
    """

    _logger: ClassVar[FlextLogger] = FlextLogger(__name__)
    _workspace_root: ClassVar[Path] = (
        Path(__file__).resolve().parent.parent.parent.parent
    )
    _resolved_admin_credentials: ClassVar[list[tuple[str, str] | None]] = [None]

    class FileLock:
        """File-based locking for pytest-xdist parallel test isolation."""

        def __init__(self, lock_file: Path) -> None:
            self.lock_file = lock_file
            self._fd: int | None = None
            self._file_obj: TextIO | None = None

        def __enter__(self) -> None:
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
            if self._fd is not None:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            if self._file_obj is not None:
                self._file_obj.close()
            self.lock_file.unlink(missing_ok=True)

    class DNSTracker:
        """Thread-safe tracker for created LDAP DNs during test sessions."""

        def __init__(self) -> None:
            self._created_dns: set[str] = set()
            self._lock = Lock()

        def add(self, dn: str) -> None:
            with self._lock:
                self._created_dns.add(dn)

        def get_all(self) -> set[str]:
            with self._lock:
                return self._created_dns.copy()

    @staticmethod
    def get_docker_control(worker_id: str = "master") -> tk:
        """Create tk instance for Docker container management."""
        return tk(
            workspace_root=_DockerInfraUtils._workspace_root,
            worker_id=worker_id,
        )

    @staticmethod
    def get_admin_credentials() -> tuple[str, str]:
        """Resolve LDAP admin credentials, trying env vars then known defaults."""
        if _DockerInfraUtils._resolved_admin_credentials[0] is not None:
            return _DockerInfraUtils._resolved_admin_credentials[0]
        d = c.Ldap.Tests.Docker
        env_dn = os.getenv("FLEXT_LDAP_BIND_DN")
        env_password = os.getenv("FLEXT_LDAP_BIND_PASSWORD")
        candidates: list[tuple[str, str]] = []
        if env_dn and env_password:
            candidates.append((env_dn, env_password))
        candidates.extend([
            (d.ADMIN_DN, d.ADMIN_PASSWORD),
            (d.LEGACY_ADMIN_DN, d.LEGACY_ADMIN_PASSWORD),
        ])
        for candidate_dn, candidate_password in candidates:
            try:
                server = FlextLdapUtilities.Ldap.create_bare_server(
                    c.LOCALHOST, port=d.PORT
                )
                test_conn = FlextLdapUtilities.Ldap.create_connection(
                    server,
                    user=candidate_dn,
                    password=candidate_password,
                    auto_bind=True,
                    receive_timeout=1,
                )
                if test_conn.bound:
                    FlextLdapLdap3Wrappers.unbind(test_conn)
                    _DockerInfraUtils._resolved_admin_credentials[0] = (
                        candidate_dn,
                        candidate_password,
                    )
                    return (candidate_dn, candidate_password)
            except (ConnectionError, OSError, ValueError):
                continue
        _DockerInfraUtils._resolved_admin_credentials[0] = (
            d.ADMIN_DN,
            d.ADMIN_PASSWORD,
        )
        return (d.ADMIN_DN, d.ADMIN_PASSWORD)

    @staticmethod
    def ensure_basic_ldap_structure() -> None:
        """Create ou=people, ou=groups, ou=services if missing."""
        d = c.Ldap.Tests.Docker
        try:
            admin_dn, admin_password = _DockerInfraUtils.get_admin_credentials()
            server = FlextLdapUtilities.Ldap.create_server_from_url(
                f"ldap://{c.LOCALHOST}:{d.PORT}",
                get_info="NO_INFO",
            )
            conn = FlextLdapUtilities.Ldap.create_connection(
                server,
                user=admin_dn,
                password=admin_password,
                auto_bind=True,
            )
            for ou_name in c.Ldap.Tests.Docker.OU_NAMES:
                conn.search(
                    d.BASE_DN,
                    f"(ou={ou_name})",
                    attributes=list(c.Ldap.Tests.Docker.OU_SEARCH_ATTRS),
                )
                if not conn.entries:
                    FlextLdapLdap3Wrappers.add(
                        conn,
                        f"ou={ou_name},{d.BASE_DN}",
                        ["organizationalUnit", "top"],
                        {
                            "ou": [ou_name],
                            "description": [
                                f"Organizational unit for {ou_name} entries",
                            ],
                        },
                    )
                    _DockerInfraUtils._logger.debug("Created ou=%s", ou_name)
            FlextLdapLdap3Wrappers.unbind(conn)
            _DockerInfraUtils._logger.info("Basic LDAP structure verified/created")
        except Exception as e:
            _DockerInfraUtils._logger.warning(
                "Failed to ensure basic LDAP structure",
                error=e,
            )


__all__ = [
    "_DockerInfraUtils",
]

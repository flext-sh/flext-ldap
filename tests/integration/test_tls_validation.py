"""LDAPS certificate validation against a real TLS-enabled LDAP server.

Requires a local untracked ``.env`` declaring an LDAPS endpoint
(``FLEXT_LDAP_TEST_LDAPS_URL``) whose certificate names only
``FLEXT_LDAP_TEST_TLS_SERVER_NAME`` (not the endpoint host), the CA that
signed it (``FLEXT_LDAP_TEST_TLS_CA_FILE``), an unrelated CA
(``FLEXT_LDAP_TEST_TLS_WRONG_CA_FILE``), and bind credentials. The shared
connectivity owner skips these tests before setup when that environment is
absent or unreachable.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from tests import c, ldap, tm, u

pytestmark = [
    pytest.mark.integration,
    pytest.mark.connectivity(
        required_vars=c.Ldap.Tests.TLS_REQUIRED_VARS,
        url_var=c.Ldap.Tests.TLS_URL_VAR,
    ),
]


@pytest.mark.usefixtures("disconnected")
class TestsFlextLdapTlsValidation:
    """Certificate and hostname validation through ``ldap.connect``."""

    @pytest.fixture
    @staticmethod
    def disconnected() -> Iterator[None]:
        """Start and end every scenario from a disconnected client."""
        ldap.disconnect()
        yield
        ldap.disconnect()

    @staticmethod
    def test_trusted_ca_and_matching_name_bind() -> None:
        """The signing CA plus the certificate name binds successfully."""
        config = u.Ldap.Tests.create_tls_connection_config(
            ca_file_var=c.Ldap.Tests.TLS_CA_FILE_VAR,
            server_name_var=c.Ldap.Tests.TLS_SERVER_NAME_VAR,
        )

        tm.ok(ldap.connect(config))
        tm.ok(ldap.is_connected)

    @staticmethod
    def test_untrusted_ca_fails() -> None:
        """A CA that did not sign the server certificate fails the connection."""
        config = u.Ldap.Tests.create_tls_connection_config(
            ca_file_var=c.Ldap.Tests.TLS_WRONG_CA_FILE_VAR,
            server_name_var=c.Ldap.Tests.TLS_SERVER_NAME_VAR,
        )

        error = tm.fail(ldap.connect(config))

        tm.that(error, contains=c.Ldap.Tests.TLS_CERTIFICATE_ERROR)
        tm.fail(ldap.is_connected)

    @staticmethod
    def test_hostname_mismatch_fails() -> None:
        """A trusted certificate that does not name the endpoint host fails."""
        config = u.Ldap.Tests.create_tls_connection_config(
            ca_file_var=c.Ldap.Tests.TLS_CA_FILE_VAR,
            server_name_var=None,
        )

        error = tm.fail(ldap.connect(config))

        tm.that(error, contains=c.Ldap.Tests.TLS_HOSTNAME_ERROR)
        tm.fail(ldap.is_connected)

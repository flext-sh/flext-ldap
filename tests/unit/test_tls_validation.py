"""Behavioral unit tests for the LDAPS/StartTLS certificate validation policy.

The connection configuration owns ``tls_validate``, ``ca_certs_file`` and
``server_name``; the server builder derives the ldap3 TLS policy from them.
The LDAP settings carry the same options and the connection configuration
built from them stays their single validator.
Everything here is construction only: no network call happens.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests import TestsFlextLdapSettings, c, m, u

pytestmark = [pytest.mark.unit]


class TestsFlextLdapTlsValidation:
    """TLS policy derivation, asserted through the public facades only."""

    @pytest.fixture
    @staticmethod
    def ca_file(tmp_path: Path) -> Path:
        """Provide a CA bundle path owned by the test.

        Returns:
            The resulting ``Path``.

        """
        path = tmp_path / c.Ldap.Tests.TLS_CA_FILENAME
        path.write_text(c.Ldap.Tests.TLS_CA_FILENAME, encoding="utf-8")
        return path

    @staticmethod
    @pytest.mark.parametrize(
        ("use_ssl", "use_tls"),
        [(True, False), (False, True)],
    )
    def test_tls_requires_certificate_validation_by_default(
        *,
        use_ssl: bool,
        use_tls: bool,
    ) -> None:
        """LDAPS and StartTLS verify the peer certificate unless told otherwise."""
        config = m.Ldap.ConnectionConfig(use_ssl=use_ssl, use_tls=use_tls)

        server = u.Ldap.create_connection_server(config)

        tls = u.Ldap.Tests.not_none(server.tls)
        u.Ldap.Tests.that(
            tls.validate,
            eq=c.Ldap.TLS_VERIFY_MODE_BY_VALIDATION[c.Ldap.DEFAULT_TLS_VALIDATION],
        )
        u.Ldap.Tests.that(tls.ca_certs_file, none=True)
        u.Ldap.Tests.that(tls.sni, none=True)
        u.Ldap.Tests.that(tls.valid_names, none=True)

    @staticmethod
    def test_tls_policy_carries_ca_bundle_and_server_name(ca_file: Path) -> None:
        """The CA bundle and server name reach the TLS policy, SNI and name check."""
        config = m.Ldap.ConnectionConfig(
            use_ssl=True,
            ca_certs_file=ca_file,
            server_name=c.Ldap.Tests.TLS_SERVER_NAME,
        )

        tls = u.Ldap.Tests.not_none(u.Ldap.create_connection_server(config).tls)

        u.Ldap.Tests.that(tls.ca_certs_file, eq=str(ca_file))
        u.Ldap.Tests.that(tls.sni, eq=c.Ldap.Tests.TLS_SERVER_NAME)
        u.Ldap.Tests.that(tls.valid_names, eq=[c.Ldap.Tests.TLS_SERVER_NAME])

    @staticmethod
    def test_disabled_validation_is_explicit() -> None:
        """Only the explicit NONE mode turns certificate verification off."""
        config = m.Ldap.ConnectionConfig(
            use_ssl=True,
            tls_validate=c.Ldap.TlsValidation.NONE,
        )

        tls = u.Ldap.Tests.not_none(u.Ldap.create_connection_server(config).tls)

        u.Ldap.Tests.that(
            tls.validate,
            eq=c.Ldap.TLS_VERIFY_MODE_BY_VALIDATION[c.Ldap.TlsValidation.NONE],
        )

    @staticmethod
    def test_cleartext_connection_carries_no_tls_policy() -> None:
        """A plain LDAP connection builds no TLS policy."""
        server = u.Ldap.create_connection_server(m.Ldap.ConnectionConfig())

        u.Ldap.Tests.that(server.tls, none=True)

    @staticmethod
    def test_tls_options_without_tls_are_rejected() -> None:
        """TLS options that cannot take effect fail validation."""
        with u.Tests.raises(
            c.ValidationError,
            match=c.Ldap.Tests.TLS_OPTIONS_REQUIRE_TLS_ERROR,
        ):
            m.Ldap.ConnectionConfig(server_name=c.Ldap.Tests.TLS_SERVER_NAME)

    @staticmethod
    def test_ca_bundle_with_disabled_validation_is_rejected(ca_file: Path) -> None:
        """A CA bundle contradicts disabled validation and fails validation."""
        with u.Tests.raises(
            c.ValidationError,
            match=c.Ldap.Tests.TLS_CA_CONTRADICTS_NONE_ERROR,
        ):
            m.Ldap.ConnectionConfig(
                use_ssl=True,
                tls_validate=c.Ldap.TlsValidation.NONE,
                ca_certs_file=ca_file,
            )

    @staticmethod
    def test_missing_ca_bundle_is_rejected(tmp_path: Path) -> None:
        """A CA bundle path that is not a file fails validation."""
        with u.Tests.raises(c.ValidationError):
            m.Ldap.ConnectionConfig(
                use_ssl=True,
                ca_certs_file=tmp_path / c.Ldap.Tests.TLS_CA_FILENAME,
            )

    @staticmethod
    def test_settings_tls_vocabulary_matches_validation_modes() -> None:
        """The settings TLS vocabulary and default mirror the validation modes."""
        ldap_settings = TestsFlextLdapSettings.LdapSettings
        schema = ldap_settings.model_json_schema()["properties"]["tls_validate"]

        u.Ldap.Tests.that(
            list(schema["enum"]),
            eq=[mode.value for mode in c.Ldap.TlsValidation],
        )
        u.Ldap.Tests.that(
            ldap_settings().tls_validate,
            eq=c.Ldap.DEFAULT_TLS_VALIDATION.value,
        )

    @staticmethod
    def test_settings_tls_options_reach_connection_config(ca_file: Path) -> None:
        """Settings TLS options survive the build of the connection config."""
        cfg = TestsFlextLdapSettings(
            Ldap=TestsFlextLdapSettings.LdapSettings(
                use_ssl=True,
                ca_certs_file=ca_file,
                server_name=c.Ldap.Tests.TLS_SERVER_NAME,
            ),
        )

        config = m.Ldap.ConnectionConfig.model_validate(cfg.Ldap.model_dump())

        u.Ldap.Tests.that(config.tls_validate, eq=c.Ldap.DEFAULT_TLS_VALIDATION)
        u.Ldap.Tests.that(config.ca_certs_file, eq=ca_file)
        u.Ldap.Tests.that(config.server_name, eq=c.Ldap.Tests.TLS_SERVER_NAME)

    @staticmethod
    def test_settings_disabled_validation_reaches_connection_config() -> None:
        """An explicit NONE mode in settings reaches the connection config."""
        cfg = TestsFlextLdapSettings(
            Ldap=TestsFlextLdapSettings.LdapSettings(
                use_tls=True,
                tls_validate=c.Ldap.TlsValidation.NONE.value,
                server_name=c.Ldap.Tests.TLS_SERVER_NAME,
            ),
        )

        config = m.Ldap.ConnectionConfig.model_validate(cfg.Ldap.model_dump())

        u.Ldap.Tests.that(config.tls_validate, eq=c.Ldap.TlsValidation.NONE)
        u.Ldap.Tests.that(config.ca_certs_file, none=True)
        u.Ldap.Tests.that(config.server_name, eq=c.Ldap.Tests.TLS_SERVER_NAME)

    @staticmethod
    def test_settings_tls_options_without_tls_are_rejected() -> None:
        """Connection config rejects settings TLS options without LDAPS/StartTLS."""
        cfg = TestsFlextLdapSettings(
            Ldap=TestsFlextLdapSettings.LdapSettings(
                server_name=c.Ldap.Tests.TLS_SERVER_NAME,
            ),
        )

        with u.Tests.raises(
            c.ValidationError,
            match=c.Ldap.Tests.TLS_OPTIONS_REQUIRE_TLS_ERROR,
        ):
            m.Ldap.ConnectionConfig.model_validate(cfg.Ldap.model_dump())

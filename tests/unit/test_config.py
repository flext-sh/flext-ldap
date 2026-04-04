"""Unit tests for FlextLdapSettings.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from flext_ldap import FlextLdapSettings
from tests import c

pytestmark = pytest.mark.unit


class TestsFlextLdapSettings:
    @pytest.fixture(autouse=True)
    def reset_settings_singleton(self) -> None:
        FlextLdapSettings.reset_for_testing()

    # ── Defaults contract ──────────────────────────────────────────────

    def test_defaults(self) -> None:
        cfg = FlextLdapSettings()
        tm.that(cfg.host, eq=c.LOCALHOST)
        tm.that(
            cfg.port,
            gte=c.Ldap.Tests.Config.PORT_MIN,
            lte=c.Ldap.Tests.Config.PORT_MAX,
        )
        tm.that(not cfg.use_ssl, eq=True)
        tm.that(not cfg.use_tls, eq=True)

    # ── Custom initialization ──────────────────────────────────────────

    def test_custom_values(self) -> None:
        cfg = FlextLdapSettings(
            host=c.Ldap.Tests.Config.EXAMPLE_HOST,
            port=c.Ldap.Tests.Config.LDAPS_PORT,
            use_ssl=True,
            bind_dn=c.Ldap.Tests.BindCredentials.ADMIN_DN,
            bind_password=c.Ldap.Tests.BindCredentials.ADMIN_PASSWORD,
        )
        tm.that(cfg.host, eq=c.Ldap.Tests.Config.EXAMPLE_HOST)
        tm.that(cfg.port, eq=c.Ldap.Tests.Config.LDAPS_PORT)
        tm.that(cfg.use_ssl, eq=True)
        tm.that(cfg.bind_dn, eq=c.Ldap.Tests.BindCredentials.ADMIN_DN)
        tm.that(cfg.bind_password, eq=c.Ldap.Tests.BindCredentials.ADMIN_PASSWORD)

    # ── Port validation ────────────────────────────────────────────────

    @pytest.mark.parametrize(
        c.Ldap.Tests.FieldNames.PORT,
        [
            c.Ldap.Tests.Config.PORT_MIN,
            c.Ldap.ConnectionDefaults.PORT,
            c.Ldap.Tests.Config.LDAPS_PORT,
            c.Ldap.Tests.Config.PORT_MAX,
        ],
    )
    def test_port_valid(self, port: int) -> None:
        tm.that(FlextLdapSettings(port=port).port, eq=port)

    def test_port_field_constraints(self) -> None:
        field = FlextLdapSettings.model_fields[c.Ldap.Tests.FieldNames.PORT]
        tm.that(field.default, eq=c.Ldap.ConnectionDefaults.PORT)
        settings = FlextLdapSettings(port=c.Ldap.ConnectionDefaults.PORT)
        tm.that(settings.port, eq=c.Ldap.ConnectionDefaults.PORT)

    # ── Host values ────────────────────────────────────────────────────

    @pytest.mark.parametrize(
        c.Ldap.Tests.FieldNames.HOST,
        [
            c.LOCALHOST,
            c.Ldap.Tests.Config.EXAMPLE_HOST,
            c.Ldap.Tests.Config.IP_HOST,
            "",
        ],
    )
    def test_host(self, host: str) -> None:
        tm.that(FlextLdapSettings(host=host).host, eq=host)

    # ── SSL/TLS combinations ───────────────────────────────────────────

    @pytest.mark.parametrize(("ssl", "tls"), c.Ldap.Tests.Config.SSL_TLS_COMBOS)
    def test_tls_options(self, ssl: bool, tls: bool) -> None:
        cfg = FlextLdapSettings(use_ssl=ssl, use_tls=tls)
        tm.that(cfg.use_ssl, eq=ssl)
        tm.that(cfg.use_tls, eq=tls)

    # ── Bind credentials ───────────────────────────────────────────────

    def test_bind_credentials_stored(self) -> None:
        cfg = FlextLdapSettings(
            bind_dn=c.Ldap.Tests.BindCredentials.ADMIN_DN,
            bind_password=c.Ldap.Tests.BindCredentials.ADMIN_PASSWORD,
        )
        tm.that(cfg.bind_dn, eq=c.Ldap.Tests.BindCredentials.ADMIN_DN)
        tm.that(cfg.bind_password, eq=c.Ldap.Tests.BindCredentials.ADMIN_PASSWORD)

    def test_bind_credentials_empty(self) -> None:
        cfg = FlextLdapSettings(bind_dn="", bind_password="")
        tm.that(cfg.bind_dn, eq="")
        tm.that(cfg.bind_password, eq="")

    # ── Pydantic model features ────────────────────────────────────────

    def test_model_config(self) -> None:
        tm.that(
            FlextLdapSettings.model_config.get("env_prefix"),
            eq=c.Ldap.Tests.Config.ENV_PREFIX,
        )
        tm.that(not FlextLdapSettings.model_config.get("case_sensitive"), eq=True)

    def test_field_descriptions(self) -> None:
        fields = FlextLdapSettings.model_fields
        tm.that(fields[c.Ldap.Tests.FieldNames.HOST].description, none=False)
        tm.that(fields[c.Ldap.Tests.FieldNames.PORT].description, none=False)

    def test_serialization(self) -> None:
        data = FlextLdapSettings(
            host=c.Ldap.Tests.Config.EXAMPLE_HOST,
            port=c.Ldap.Tests.Config.LDAPS_PORT,
            use_ssl=True,
        ).model_dump()
        tm.that(data[c.Ldap.Tests.FieldNames.HOST], eq=c.Ldap.Tests.Config.EXAMPLE_HOST)
        tm.that(data[c.Ldap.Tests.FieldNames.PORT], eq=c.Ldap.Tests.Config.LDAPS_PORT)
        tm.that(data["use_ssl"], eq=True)

    def test_json_schema(self) -> None:
        schema = FlextLdapSettings.model_json_schema()
        tm.that(
            schema,
            keys=[c.Ldap.Tests.FieldNames.PROPERTIES, c.Ldap.Tests.FieldNames.TYPE],
        )
        tm.that(
            dict(schema[c.Ldap.Tests.FieldNames.PROPERTIES]),
            keys=[c.Ldap.Tests.FieldNames.HOST, c.Ldap.Tests.FieldNames.PORT],
        )

    def test_deep_copy(self) -> None:
        original = FlextLdapSettings(
            host=c.Ldap.Tests.Config.ORIGINAL_HOST,
            port=c.Ldap.ConnectionDefaults.PORT,
        )
        copied = original.model_copy(deep=True)
        tm.that(copied, is_=FlextLdapSettings, none=False)
        tm.that(
            original.model_dump()[c.Ldap.Tests.FieldNames.PORT],
            eq=copied.model_dump()[c.Ldap.Tests.FieldNames.PORT],
        )

    # ── Singleton behavior ─────────────────────────────────────────────

    def test_singleton_shares_state(self) -> None:
        c1 = FlextLdapSettings(
            host=c.Ldap.Tests.Config.FIRST_HOST,
            port=c.Ldap.ConnectionDefaults.PORT,
        )
        c2 = FlextLdapSettings(
            host=c.Ldap.Tests.Config.SECOND_HOST,
            port=c.Ldap.Tests.Config.LDAPS_PORT,
        )
        tm.that(c1, eq=c2)
        tm.that(c1.host, eq=c2.host)

    def test_model_dump_keys(self) -> None:
        dump = FlextLdapSettings().model_dump()
        tm.that(
            dump,
            keys=[
                c.Ldap.Tests.FieldNames.BIND_DN,
                c.Ldap.Tests.FieldNames.BIND_PASSWORD,
            ],
        )
        tm.that(dump, lacks_keys=[c.Ldap.Tests.FieldNames.BASE_DN])

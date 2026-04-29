"""Unit tests for FlextLdapSettings.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap import FlextLdapSettings
from tests import c, u

pytestmark = pytest.mark.unit


class TestsFlextLdapConfig:
    @pytest.fixture(autouse=True)
    def reset_settings_singleton(self) -> None:
        FlextLdapSettings.reset_for_testing()

    # ── Defaults contract ──────────────────────────────────────────────

    def test_defaults(self) -> None:
        cfg = FlextLdapSettings()
        u.Ldap.Tests.that(cfg.host, eq=c.LOCALHOST)
        u.Ldap.Tests.that(
            cfg.port, gte=c.Ldap.Tests.CONFIG_PORT_MIN, lte=c.Ldap.Tests.CONFIG_PORT_MAX
        )
        u.Ldap.Tests.that(not cfg.use_ssl, eq=True)
        u.Ldap.Tests.that(not cfg.use_tls, eq=True)

    # ── Custom initialization ──────────────────────────────────────────

    def test_custom_values(self) -> None:
        cfg = FlextLdapSettings(
            host=c.Ldap.Tests.CONFIG_EXAMPLE_HOST,
            port=c.Ldap.Tests.CONFIG_LDAPS_PORT,
            use_ssl=True,
            bind_dn=c.Ldap.Tests.BIND_ADMIN_DN,
            bind_password=c.Ldap.Tests.BIND_ADMIN_PASSWORD,
        )
        u.Ldap.Tests.that(cfg.host, eq=c.Ldap.Tests.CONFIG_EXAMPLE_HOST)
        u.Ldap.Tests.that(cfg.port, eq=c.Ldap.Tests.CONFIG_LDAPS_PORT)
        u.Ldap.Tests.that(cfg.use_ssl, eq=True)
        u.Ldap.Tests.that(cfg.bind_dn, eq=c.Ldap.Tests.BIND_ADMIN_DN)
        u.Ldap.Tests.that(cfg.bind_password, eq=c.Ldap.Tests.BIND_ADMIN_PASSWORD)

    # ── Port validation ────────────────────────────────────────────────

    @pytest.mark.parametrize(
        c.Ldap.Tests.FIELD_PORT,
        [
            c.Ldap.Tests.CONFIG_PORT_MIN,
            c.Ldap.PORT,
            c.Ldap.Tests.CONFIG_LDAPS_PORT,
            c.Ldap.Tests.CONFIG_PORT_MAX,
        ],
    )
    def test_port_valid(self, port: int) -> None:
        u.Ldap.Tests.that(FlextLdapSettings(port=port).port, eq=port)

    def test_port_field_constraints(self) -> None:
        field = FlextLdapSettings.model_fields[c.Ldap.Tests.FIELD_PORT]
        u.Ldap.Tests.that(field.default, eq=c.Ldap.PORT)
        settings = FlextLdapSettings(port=c.Ldap.PORT)
        u.Ldap.Tests.that(settings.port, eq=c.Ldap.PORT)

    # ── Host values ────────────────────────────────────────────────────

    @pytest.mark.parametrize(
        c.Ldap.Tests.FIELD_HOST,
        [
            c.LOCALHOST,
            c.Ldap.Tests.CONFIG_EXAMPLE_HOST,
            c.Ldap.Tests.CONFIG_IP_HOST,
            "",
        ],
    )
    def test_host(self, host: str) -> None:
        u.Ldap.Tests.that(FlextLdapSettings(host=host).host, eq=host)

    # ── SSL/TLS combinations ───────────────────────────────────────────

    @pytest.mark.parametrize(("ssl", "tls"), c.Ldap.Tests.CONFIG_SSL_TLS_COMBOS)
    def test_tls_options(self, ssl: bool, tls: bool) -> None:
        cfg = FlextLdapSettings(use_ssl=ssl, use_tls=tls)
        u.Ldap.Tests.that(cfg.use_ssl, eq=ssl)
        u.Ldap.Tests.that(cfg.use_tls, eq=tls)

    # ── Bind credentials ───────────────────────────────────────────────

    def test_bind_credentials_stored(self) -> None:
        cfg = FlextLdapSettings(
            bind_dn=c.Ldap.Tests.BIND_ADMIN_DN,
            bind_password=c.Ldap.Tests.BIND_ADMIN_PASSWORD,
        )
        u.Ldap.Tests.that(cfg.bind_dn, eq=c.Ldap.Tests.BIND_ADMIN_DN)
        u.Ldap.Tests.that(cfg.bind_password, eq=c.Ldap.Tests.BIND_ADMIN_PASSWORD)

    def test_bind_credentials_empty(self) -> None:
        cfg = FlextLdapSettings(bind_dn="", bind_password="")
        u.Ldap.Tests.that(cfg.bind_dn, eq="")
        u.Ldap.Tests.that(cfg.bind_password, eq="")

    # ── Pydantic model features ────────────────────────────────────────

    def test_model_config(self) -> None:
        u.Ldap.Tests.that(
            FlextLdapSettings.model_config.get("env_prefix"),
            eq=c.Ldap.Tests.CONFIG_ENV_PREFIX,
        )
        u.Ldap.Tests.that(
            not FlextLdapSettings.model_config.get("case_sensitive"), eq=True
        )

    def test_field_descriptions(self) -> None:
        fields = FlextLdapSettings.model_fields
        u.Ldap.Tests.that(fields[c.Ldap.Tests.FIELD_HOST].description, none=False)
        u.Ldap.Tests.that(fields[c.Ldap.Tests.FIELD_PORT].description, none=False)

    def test_serialization(self) -> None:
        data = FlextLdapSettings(
            host=c.Ldap.Tests.CONFIG_EXAMPLE_HOST,
            port=c.Ldap.Tests.CONFIG_LDAPS_PORT,
            use_ssl=True,
        ).model_dump()
        u.Ldap.Tests.that(
            data[c.Ldap.Tests.FIELD_HOST], eq=c.Ldap.Tests.CONFIG_EXAMPLE_HOST
        )
        u.Ldap.Tests.that(
            data[c.Ldap.Tests.FIELD_PORT], eq=c.Ldap.Tests.CONFIG_LDAPS_PORT
        )
        u.Ldap.Tests.that(data["use_ssl"], eq=True)

    def test_json_schema(self) -> None:
        schema = FlextLdapSettings.model_json_schema()
        u.Ldap.Tests.that(
            schema, keys=[c.Ldap.Tests.FIELD_PROPERTIES, c.Ldap.Tests.FIELD_TYPE]
        )
        u.Ldap.Tests.that(
            dict(schema[c.Ldap.Tests.FIELD_PROPERTIES]),
            keys=[c.Ldap.Tests.FIELD_HOST, c.Ldap.Tests.FIELD_PORT],
        )

    def test_deep_copy(self) -> None:
        original = FlextLdapSettings(
            host=c.Ldap.Tests.CONFIG_ORIGINAL_HOST,
            port=c.Ldap.PORT,
        )
        copied = original.clone()
        u.Ldap.Tests.that(copied, is_=FlextLdapSettings, none=False)
        u.Ldap.Tests.that(
            original.model_dump()[c.Ldap.Tests.FIELD_PORT],
            eq=copied.model_dump()[c.Ldap.Tests.FIELD_PORT],
        )

    # ── Singleton behavior ─────────────────────────────────────────────

    def test_singleton_shares_state(self) -> None:
        c1 = FlextLdapSettings(
            host=c.Ldap.Tests.CONFIG_FIRST_HOST,
            port=c.Ldap.PORT,
        )
        c2 = FlextLdapSettings(
            host=c.Ldap.Tests.CONFIG_SECOND_HOST,
            port=c.Ldap.Tests.CONFIG_LDAPS_PORT,
        )
        u.Ldap.Tests.that(c1, eq=c2)
        u.Ldap.Tests.that(c1.host, eq=c2.host)

    def test_model_dump_keys(self) -> None:
        dump = FlextLdapSettings().model_dump()
        u.Ldap.Tests.that(
            dump,
            keys=[
                c.Ldap.Tests.FIELD_BIND_DN,
                c.Ldap.Tests.FIELD_BIND_PASSWORD,
            ],
        )
        u.Ldap.Tests.that(dump, lacks_keys=[c.Ldap.Tests.FIELD_BASE_DN])

"""Unit tests for the namespaced LDAP test settings.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from tests.constants import c
from tests.settings import TestsFlextLdapSettings
from tests.utilities import u

pytestmark = pytest.mark.unit


class TestsFlextLdapConfig:
    # ── Defaults contract ──────────────────────────────────────────────

    def test_defaults(self) -> None:
        cfg = TestsFlextLdapSettings()
        u.Ldap.Tests.that(cfg.Ldap.host, eq=c.LOCALHOST)
        u.Ldap.Tests.that(
            cfg.Ldap.port,
            gte=c.Ldap.Tests.CONFIG_PORT_MIN,
            lte=c.Ldap.Tests.CONFIG_PORT_MAX,
        )
        u.Ldap.Tests.that(not cfg.Ldap.use_ssl, eq=True)
        u.Ldap.Tests.that(not cfg.Ldap.use_tls, eq=True)

    # ── Custom initialization ──────────────────────────────────────────

    def test_custom_values(self) -> None:
        cfg = TestsFlextLdapSettings(
            Ldap={
                c.Ldap.Tests.FIELD_HOST.value: c.Ldap.Tests.CONFIG_EXAMPLE_HOST,
                c.Ldap.Tests.FIELD_PORT.value: c.Ldap.Tests.CONFIG_LDAPS_PORT,
                "use_ssl": True,
                c.Ldap.Tests.FIELD_BIND_DN.value: c.Ldap.Tests.BIND_ADMIN_DN,
                c.Ldap.Tests.FIELD_BIND_PASSWORD.value: c.Ldap.Tests.BIND_ADMIN_PASSWORD,
            },
        )
        u.Ldap.Tests.that(cfg.Ldap.host, eq=c.Ldap.Tests.CONFIG_EXAMPLE_HOST)
        u.Ldap.Tests.that(cfg.Ldap.port, eq=c.Ldap.Tests.CONFIG_LDAPS_PORT)
        u.Ldap.Tests.that(cfg.Ldap.use_ssl, eq=True)
        u.Ldap.Tests.that(cfg.Ldap.bind_dn, eq=c.Ldap.Tests.BIND_ADMIN_DN)
        u.Ldap.Tests.that(
            cfg.Ldap.bind_password,
            eq=c.Ldap.Tests.BIND_ADMIN_PASSWORD,
        )

    # ── Port validation ────────────────────────────────────────────────

    @pytest.mark.parametrize(
        c.Ldap.Tests.FIELD_PORT,
        c.Ldap.Tests.CONFIG_VALID_PORTS,
    )
    def test_port_valid(self, port: int) -> None:
        u.Ldap.Tests.that(
            TestsFlextLdapSettings(
                Ldap={c.Ldap.Tests.FIELD_PORT.value: port},
            ).Ldap.port,
            eq=port,
        )

    # ── Host values ────────────────────────────────────────────────────

    @pytest.mark.parametrize(
        c.Ldap.Tests.FIELD_HOST,
        c.Ldap.Tests.CONFIG_HOST_CASES,
    )
    def test_host(self, host: str) -> None:
        u.Ldap.Tests.that(
            TestsFlextLdapSettings(
                Ldap={c.Ldap.Tests.FIELD_HOST.value: host},
            ).Ldap.host,
            eq=host,
        )

    # ── SSL/TLS combinations ───────────────────────────────────────────

    @pytest.mark.parametrize(("ssl", "tls"), c.Ldap.Tests.CONFIG_SSL_TLS_COMBOS)
    def test_tls_options(self, ssl: bool, tls: bool) -> None:
        cfg = TestsFlextLdapSettings(Ldap={"use_ssl": ssl, "use_tls": tls})
        u.Ldap.Tests.that(cfg.Ldap.use_ssl, eq=ssl)
        u.Ldap.Tests.that(cfg.Ldap.use_tls, eq=tls)

    # ── Bind credentials ───────────────────────────────────────────────

    def test_bind_credentials_stored(self) -> None:
        cfg = TestsFlextLdapSettings(
            Ldap={
                c.Ldap.Tests.FIELD_BIND_DN.value: c.Ldap.Tests.BIND_ADMIN_DN,
                c.Ldap.Tests.FIELD_BIND_PASSWORD.value: c.Ldap.Tests.BIND_ADMIN_PASSWORD,
            },
        )
        u.Ldap.Tests.that(cfg.Ldap.bind_dn, eq=c.Ldap.Tests.BIND_ADMIN_DN)
        u.Ldap.Tests.that(
            cfg.Ldap.bind_password,
            eq=c.Ldap.Tests.BIND_ADMIN_PASSWORD,
        )

    def test_bind_credentials_empty(self) -> None:
        cfg = TestsFlextLdapSettings(
            Ldap={
                c.Ldap.Tests.FIELD_BIND_DN.value: "",
                c.Ldap.Tests.FIELD_BIND_PASSWORD.value: "",
            },
        )
        u.Ldap.Tests.that(cfg.Ldap.bind_dn, eq="")
        u.Ldap.Tests.that(cfg.Ldap.bind_password, eq="")

    # ── Pydantic model features ────────────────────────────────────────

    def test_serialization(self) -> None:
        data = TestsFlextLdapSettings(
            Ldap={
                c.Ldap.Tests.FIELD_HOST.value: c.Ldap.Tests.CONFIG_EXAMPLE_HOST,
                c.Ldap.Tests.FIELD_PORT.value: c.Ldap.Tests.CONFIG_LDAPS_PORT,
                "use_ssl": True,
            },
        ).model_dump()
        ldap_dump = data["Ldap"]
        u.Ldap.Tests.that(
            ldap_dump[c.Ldap.Tests.FIELD_HOST],
            eq=c.Ldap.Tests.CONFIG_EXAMPLE_HOST,
        )
        u.Ldap.Tests.that(
            ldap_dump[c.Ldap.Tests.FIELD_PORT],
            eq=c.Ldap.Tests.CONFIG_LDAPS_PORT,
        )
        u.Ldap.Tests.that(ldap_dump["use_ssl"], eq=True)

    def test_json_schema(self) -> None:
        schema = TestsFlextLdapSettings.model_json_schema()
        u.Ldap.Tests.that(
            schema,
            keys=[c.Ldap.Tests.FIELD_PROPERTIES, c.Ldap.Tests.FIELD_TYPE],
        )
        ldap_schema = schema[c.Ldap.Tests.FIELD_PROPERTIES]["Ldap"]
        ldap_definition = schema["$defs"][ldap_schema["$ref"].split("/")[-1]]
        u.Ldap.Tests.that(
            dict(ldap_definition[c.Ldap.Tests.FIELD_PROPERTIES]),
            keys=[c.Ldap.Tests.FIELD_HOST, c.Ldap.Tests.FIELD_PORT],
        )

    def test_deep_copy(self) -> None:
        original = TestsFlextLdapSettings(
            Ldap={
                c.Ldap.Tests.FIELD_HOST.value: c.Ldap.Tests.CONFIG_ORIGINAL_HOST,
                c.Ldap.Tests.FIELD_PORT.value: c.Ldap.PORT,
            },
        )
        copied = original.clone()
        u.Ldap.Tests.that(copied, is_=TestsFlextLdapSettings, none=False)
        u.Ldap.Tests.that(
            original.model_dump()["Ldap"][c.Ldap.Tests.FIELD_PORT],
            eq=copied.model_dump()["Ldap"][c.Ldap.Tests.FIELD_PORT],
        )

    # ── Singleton behavior ─────────────────────────────────────────────

    def test_singleton_shares_state(self) -> None:
        c1 = TestsFlextLdapSettings(
            Ldap={
                c.Ldap.Tests.FIELD_HOST.value: c.Ldap.Tests.CONFIG_FIRST_HOST,
                c.Ldap.Tests.FIELD_PORT.value: c.Ldap.PORT,
            },
        )
        c2 = TestsFlextLdapSettings(
            Ldap={
                c.Ldap.Tests.FIELD_HOST.value: c.Ldap.Tests.CONFIG_SECOND_HOST,
                c.Ldap.Tests.FIELD_PORT.value: c.Ldap.Tests.CONFIG_LDAPS_PORT,
            },
        )
        u.Ldap.Tests.that(c1, eq=c2)
        u.Ldap.Tests.that(c1.Ldap.host, eq=c2.Ldap.host)

    def test_model_dump_keys(self) -> None:
        dump = TestsFlextLdapSettings().model_dump()
        ldap_dump = dump["Ldap"]
        u.Ldap.Tests.that(
            ldap_dump,
            keys=[
                c.Ldap.Tests.FIELD_BIND_DN,
                c.Ldap.Tests.FIELD_BIND_PASSWORD,
            ],
        )
        u.Ldap.Tests.that(ldap_dump, lacks_keys=[c.Ldap.Tests.FIELD_BASE_DN])

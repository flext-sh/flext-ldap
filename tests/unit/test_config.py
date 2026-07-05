"""Behavioral tests for the namespaced LDAP test settings.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from tests.constants import c
from tests.settings import TestsFlextLdapSettings
from tests.utilities import u

pytestmark = pytest.mark.unit

_LdapSettings = TestsFlextLdapSettings.LdapSettings


class TestsFlextLdapConfig:
    """Public-contract behavior of :class:`TestsFlextLdapSettings`.

    Every assertion targets observable state reachable through the public
    Pydantic 2 API (constructor, typed fields, ``model_dump``,
    ``model_json_schema``, ``clone``) — never private attributes or
    internal collaborators.
    """

    # ── Defaults contract ──────────────────────────────────────────────

    def test_defaults_expose_local_insecure_ldap(self) -> None:
        cfg = TestsFlextLdapSettings()

        u.Ldap.Tests.that(cfg.Ldap.host, eq=c.LOCALHOST)
        u.Ldap.Tests.that(
            cfg.Ldap.port,
            gte=c.Ldap.Tests.CONFIG_PORT_MIN,
            lte=c.Ldap.Tests.CONFIG_PORT_MAX,
        )
        u.Ldap.Tests.that(cfg.Ldap.use_ssl, eq=False)
        u.Ldap.Tests.that(cfg.Ldap.use_tls, eq=False)

    # ── Custom initialization ──────────────────────────────────────────

    def test_custom_values_are_retained_on_public_fields(self) -> None:
        cfg = TestsFlextLdapSettings(
            Ldap=_LdapSettings(
                host=c.Ldap.Tests.CONFIG_EXAMPLE_HOST,
                port=c.Ldap.Tests.CONFIG_LDAPS_PORT,
                use_ssl=True,
                bind_dn=c.Ldap.Tests.BIND_ADMIN_DN,
                bind_password=c.Ldap.Tests.BIND_ADMIN_PASSWORD,
            ),
        )

        u.Ldap.Tests.that(cfg.Ldap.host, eq=c.Ldap.Tests.CONFIG_EXAMPLE_HOST)
        u.Ldap.Tests.that(cfg.Ldap.port, eq=c.Ldap.Tests.CONFIG_LDAPS_PORT)
        u.Ldap.Tests.that(cfg.Ldap.use_ssl, eq=True)
        u.Ldap.Tests.that(cfg.Ldap.bind_dn, eq=c.Ldap.Tests.BIND_ADMIN_DN)
        u.Ldap.Tests.that(
            cfg.Ldap.bind_password,
            eq=c.Ldap.Tests.BIND_ADMIN_PASSWORD,
        )

    # ── Port validation (accepts in-range) ─────────────────────────────

    @pytest.mark.parametrize(
        c.Ldap.Tests.FIELD_PORT,
        c.Ldap.Tests.CONFIG_VALID_PORTS,
    )
    def test_in_range_port_is_accepted(self, port: int) -> None:
        u.Ldap.Tests.that(
            TestsFlextLdapSettings(
                Ldap=_LdapSettings(port=port),
            ).Ldap.port,
            eq=port,
        )

    # ── Port validation (rejects out-of-range) — error path ────────────

    @pytest.mark.parametrize("port", [0, -1, 65536, 70000, 999999])
    def test_out_of_range_port_is_rejected(self, port: int) -> None:
        with pytest.raises(c.ValidationError):
            TestsFlextLdapSettings(Ldap=_LdapSettings(port=port))

    # ── Host values ────────────────────────────────────────────────────

    @pytest.mark.parametrize(
        c.Ldap.Tests.FIELD_HOST,
        c.Ldap.Tests.CONFIG_HOST_CASES,
    )
    def test_host_is_stored_verbatim(self, host: str) -> None:
        u.Ldap.Tests.that(
            TestsFlextLdapSettings(
                Ldap=_LdapSettings(host=host),
            ).Ldap.host,
            eq=host,
        )

    # ── SSL/TLS combinations ───────────────────────────────────────────

    @pytest.mark.parametrize(("ssl", "tls"), c.Ldap.Tests.CONFIG_SSL_TLS_COMBOS)
    def test_ssl_and_tls_flags_are_independent(
        self,
        ssl: bool,
        tls: bool,
    ) -> None:
        cfg = TestsFlextLdapSettings(Ldap=_LdapSettings(use_ssl=ssl, use_tls=tls))

        u.Ldap.Tests.that(cfg.Ldap.use_ssl, eq=ssl)
        u.Ldap.Tests.that(cfg.Ldap.use_tls, eq=tls)

    # ── Bind credentials ───────────────────────────────────────────────

    def test_bind_credentials_are_stored(self) -> None:
        cfg = TestsFlextLdapSettings(
            Ldap=_LdapSettings(
                bind_dn=c.Ldap.Tests.BIND_ADMIN_DN,
                bind_password=c.Ldap.Tests.BIND_ADMIN_PASSWORD,
            ),
        )

        u.Ldap.Tests.that(cfg.Ldap.bind_dn, eq=c.Ldap.Tests.BIND_ADMIN_DN)
        u.Ldap.Tests.that(
            cfg.Ldap.bind_password,
            eq=c.Ldap.Tests.BIND_ADMIN_PASSWORD,
        )

    def test_empty_bind_credentials_are_preserved(self) -> None:
        cfg = TestsFlextLdapSettings(
            Ldap=_LdapSettings(
                bind_dn="",
                bind_password="",
            ),
        )

        u.Ldap.Tests.that(cfg.Ldap.bind_dn, eq="")
        u.Ldap.Tests.that(cfg.Ldap.bind_password, eq="")

    # ── Serialization contract ─────────────────────────────────────────

    def test_model_dump_round_trips_custom_values(self) -> None:
        ldap_dump = TestsFlextLdapSettings(
            Ldap=_LdapSettings(
                host=c.Ldap.Tests.CONFIG_EXAMPLE_HOST,
                port=c.Ldap.Tests.CONFIG_LDAPS_PORT,
                use_ssl=True,
            ),
        ).model_dump()["Ldap"]

        u.Ldap.Tests.that(
            ldap_dump[c.Ldap.Tests.FIELD_HOST],
            eq=c.Ldap.Tests.CONFIG_EXAMPLE_HOST,
        )
        u.Ldap.Tests.that(
            ldap_dump[c.Ldap.Tests.FIELD_PORT],
            eq=c.Ldap.Tests.CONFIG_LDAPS_PORT,
        )
        u.Ldap.Tests.that(ldap_dump["use_ssl"], eq=True)

    def test_default_model_dump_exposes_bind_fields(self) -> None:
        ldap_dump = TestsFlextLdapSettings().model_dump()["Ldap"]

        u.Ldap.Tests.that(
            ldap_dump,
            keys=[
                c.Ldap.Tests.FIELD_BIND_DN,
                c.Ldap.Tests.FIELD_BIND_PASSWORD,
            ],
        )
        u.Ldap.Tests.that(ldap_dump, lacks_keys=[c.Ldap.Tests.FIELD_BASE_DN])

    def test_json_schema_advertises_ldap_section(self) -> None:
        schema = TestsFlextLdapSettings.model_json_schema()

        u.Ldap.Tests.that(
            schema,
            keys=[c.Ldap.Tests.FIELD_PROPERTIES, c.Ldap.Tests.FIELD_TYPE],
        )
        u.Ldap.Tests.that(
            dict(schema[c.Ldap.Tests.FIELD_PROPERTIES]),
            keys=["Ldap"],
        )

    # ── Singleton state sharing (observable contract) ──────────────────

    def test_repeated_construction_shares_settings_state(self) -> None:
        first = TestsFlextLdapSettings(
            Ldap=_LdapSettings(
                host=c.Ldap.Tests.CONFIG_FIRST_HOST,
                port=c.Ldap.PORT,
            ),
        )
        second = TestsFlextLdapSettings(
            Ldap=_LdapSettings(
                host=c.Ldap.Tests.CONFIG_SECOND_HOST,
                port=c.Ldap.Tests.CONFIG_LDAPS_PORT,
            ),
        )

        u.Ldap.Tests.that(first, eq=second)
        u.Ldap.Tests.that(first.Ldap.host, eq=second.Ldap.host)

    # ── Clone semantics ────────────────────────────────────────────────

    def test_clone_preserves_public_state(self) -> None:
        original = TestsFlextLdapSettings(
            Ldap=_LdapSettings(
                host=c.Ldap.Tests.CONFIG_ORIGINAL_HOST,
                port=c.Ldap.PORT,
            ),
        )

        copied = original.clone()

        u.Ldap.Tests.that(copied, is_=TestsFlextLdapSettings, none=False)
        u.Ldap.Tests.that(
            copied.model_dump()["Ldap"],
            eq=original.model_dump()["Ldap"],
        )

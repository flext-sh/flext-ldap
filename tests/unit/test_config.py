"""Behavioral tests for the namespaced LDAP test settings.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from tests import TestsFlextLdapSettings, c, u

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

    @staticmethod
    def test_defaults_expose_local_insecure_ldap() -> None:
        """Verify defaults expose local insecure ldap."""
        cfg = TestsFlextLdapSettings()

        u.Tests.that(cfg.Ldap.host, eq=c.LOCALHOST)
        u.Tests.that(
            cfg.Ldap.port,
            gte=c.Tests.CONFIG_PORT_MIN,
            lte=c.Tests.CONFIG_PORT_MAX,
        )
        u.Tests.that(cfg.Ldap.use_ssl, eq=False)
        u.Tests.that(cfg.Ldap.use_tls, eq=False)

    # ── Custom initialization ──────────────────────────────────────────

    @staticmethod
    def test_custom_values_are_retained_on_public_fields() -> None:
        """Verify custom values are retained on public fields."""
        cfg = TestsFlextLdapSettings(
            Ldap=_LdapSettings(
                host=c.Tests.CONFIG_EXAMPLE_HOST,
                port=c.Tests.CONFIG_LDAPS_PORT,
                use_ssl=True,
                bind_dn=c.Tests.BIND_ADMIN_DN,
                bind_password=c.Tests.BIND_ADMIN_PASSWORD,
            ),
        )

        u.Tests.that(cfg.Ldap.host, eq=c.Tests.CONFIG_EXAMPLE_HOST)
        u.Tests.that(cfg.Ldap.port, eq=c.Tests.CONFIG_LDAPS_PORT)
        u.Tests.that(cfg.Ldap.use_ssl, eq=True)
        u.Tests.that(cfg.Ldap.bind_dn, eq=c.Tests.BIND_ADMIN_DN)
        u.Tests.that(cfg.Ldap.bind_password, eq=c.Tests.BIND_ADMIN_PASSWORD)

    # ── Port validation (accepts in-range) ─────────────────────────────

    @pytest.mark.parametrize(c.Tests.FIELD_PORT, c.Tests.CONFIG_VALID_PORTS)
    @staticmethod
    def test_in_range_port_is_accepted(port: int) -> None:
        """Verify in range port is accepted."""
        u.Tests.that(
            TestsFlextLdapSettings(Ldap=_LdapSettings(port=port)).Ldap.port,
            eq=port,
        )

    # ── Port validation (rejects out-of-range) — error path ────────────

    @pytest.mark.parametrize("port", [0, -1, 65536, 70000, 999999])
    @staticmethod
    def test_out_of_range_port_is_rejected(port: int) -> None:
        """Verify out of range port is rejected."""
        with u.Tests.raises(c.ValidationError):
            TestsFlextLdapSettings(Ldap=_LdapSettings(port=port))

    # ── Host values ────────────────────────────────────────────────────

    @pytest.mark.parametrize(c.Tests.FIELD_HOST, c.Tests.CONFIG_HOST_CASES)
    @staticmethod
    def test_host_is_stored_verbatim(host: str) -> None:
        """Verify host is stored verbatim."""
        u.Tests.that(
            TestsFlextLdapSettings(Ldap=_LdapSettings(host=host)).Ldap.host,
            eq=host,
        )

    # ── SSL/TLS combinations ───────────────────────────────────────────

    @pytest.mark.parametrize(("ssl", "tls"), c.Tests.CONFIG_SSL_TLS_COMBOS)
    @staticmethod
    def test_ssl_and_tls_flags_are_independent(*, ssl: bool, tls: bool) -> None:
        """Verify ssl and tls flags are independent."""
        cfg = TestsFlextLdapSettings(Ldap=_LdapSettings(use_ssl=ssl, use_tls=tls))

        u.Tests.that(cfg.Ldap.use_ssl, eq=ssl)
        u.Tests.that(cfg.Ldap.use_tls, eq=tls)

    # ── Bind credentials ───────────────────────────────────────────────

    @staticmethod
    def test_bind_credentials_are_stored() -> None:
        """Verify bind credentials are stored."""
        cfg = TestsFlextLdapSettings(
            Ldap=_LdapSettings(
                bind_dn=c.Tests.BIND_ADMIN_DN,
                bind_password=c.Tests.BIND_ADMIN_PASSWORD,
            ),
        )

        u.Tests.that(cfg.Ldap.bind_dn, eq=c.Tests.BIND_ADMIN_DN)
        u.Tests.that(cfg.Ldap.bind_password, eq=c.Tests.BIND_ADMIN_PASSWORD)

    @staticmethod
    def test_empty_bind_credentials_are_preserved() -> None:
        """Verify empty bind credentials are preserved."""
        cfg = TestsFlextLdapSettings(
            Ldap=_LdapSettings(
                bind_dn=c.Tests.STRING_EMPTY,
                bind_password=c.Tests.STRING_EMPTY,
            ),
        )

        u.Tests.that(cfg.Ldap.bind_dn, eq=c.Tests.STRING_EMPTY)
        u.Tests.that(cfg.Ldap.bind_password, eq=c.Tests.STRING_EMPTY)

    # ── Serialization contract ─────────────────────────────────────────

    @staticmethod
    def test_model_dump_round_trips_custom_values() -> None:
        """Verify model dump round trips custom values."""
        ldap_dump = TestsFlextLdapSettings(
            Ldap=_LdapSettings(
                host=c.Tests.CONFIG_EXAMPLE_HOST,
                port=c.Tests.CONFIG_LDAPS_PORT,
                use_ssl=True,
            ),
        ).model_dump()["Ldap"]

        u.Tests.that(
            ldap_dump[c.Tests.FIELD_HOST],
            eq=c.Tests.CONFIG_EXAMPLE_HOST,
        )
        u.Tests.that(
            ldap_dump[c.Tests.FIELD_PORT],
            eq=c.Tests.CONFIG_LDAPS_PORT,
        )
        u.Tests.that(ldap_dump["use_ssl"], eq=True)

    @staticmethod
    def test_default_model_dump_exposes_bind_fields() -> None:
        """Verify default model dump exposes bind fields."""
        ldap_dump = TestsFlextLdapSettings().model_dump()["Ldap"]

        u.Tests.that(
            ldap_dump,
            keys=[c.Tests.FIELD_BIND_DN, c.Tests.FIELD_BIND_PASSWORD],
        )
        u.Tests.that(ldap_dump, lacks_keys=[c.Tests.FIELD_BASE_DN])

    @staticmethod
    def test_json_schema_advertises_ldap_section() -> None:
        """Verify json schema advertises ldap section."""
        schema = TestsFlextLdapSettings.model_json_schema()

        u.Tests.that(
            schema,
            keys=[c.Tests.FIELD_PROPERTIES, c.Tests.FIELD_TYPE],
        )
        u.Tests.that(dict(schema[c.Tests.FIELD_PROPERTIES]), keys=["Ldap"])

    # ── Construction isolation (observable contract) ───────────────────

    @staticmethod
    def test_repeated_construction_keeps_isolated_state() -> None:
        """Verify each direct construction keeps its own values.

        Only the global lifecycle (``fetch_global``) publishes a shared
        singleton; direct construction creates an isolated instance.
        """
        first = TestsFlextLdapSettings(
            Ldap=_LdapSettings(host=c.Tests.CONFIG_FIRST_HOST, port=c.Ldap.PORT),
        )
        second = TestsFlextLdapSettings(
            Ldap=_LdapSettings(
                host=c.Tests.CONFIG_SECOND_HOST,
                port=c.Tests.CONFIG_LDAPS_PORT,
            ),
        )

        u.Tests.that(first.Ldap.host, eq=c.Tests.CONFIG_FIRST_HOST)
        u.Tests.that(second.Ldap.host, eq=c.Tests.CONFIG_SECOND_HOST)
        u.Tests.that(second.Ldap.port, eq=c.Tests.CONFIG_LDAPS_PORT)
        u.Tests.that(
            TestsFlextLdapSettings.fetch_global(),
            is_=TestsFlextLdapSettings,
        )
        u.Tests.that(first is TestsFlextLdapSettings.fetch_global(), eq=False)

    # ── Clone semantics ────────────────────────────────────────────────

    @staticmethod
    def test_clone_preserves_public_state() -> None:
        """Verify clone preserves public state."""
        original = TestsFlextLdapSettings(
            Ldap=_LdapSettings(
                host=c.Tests.CONFIG_ORIGINAL_HOST,
                port=c.Ldap.PORT,
            ),
        )

        copied = original.clone()

        u.Tests.that(copied, is_=TestsFlextLdapSettings, none=False)
        u.Tests.that(copied.model_dump()["Ldap"], eq=original.model_dump()["Ldap"])

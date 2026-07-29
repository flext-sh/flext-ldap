"""Behavioral tests for the namespaced LDAP test settings.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from tests import c, u
from tests.settings import TestsFlextLdapSettings as LdapTestSettings

pytestmark = pytest.mark.unit

_LdapSettings = LdapTestSettings.LdapSettings


class TestsFlextLdapConfig:
    """Public-contract behavior of :class:`LdapTestSettings`.

    Every assertion targets observable state reachable through the public
    Pydantic 2 API (constructor, typed fields, ``model_dump``,
    ``model_json_schema``, ``clone``) — never private attributes or
    internal collaborators.
    """

    # ── Defaults contract ──────────────────────────────────────────────

    def test_defaults_expose_local_insecure_ldap(self) -> None:
        """Verify defaults expose local insecure ldap."""
        cfg = LdapTestSettings()

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
        """Verify custom values are retained on public fields."""
        cfg = LdapTestSettings(
            Ldap=_LdapSettings(
                host=c.Ldap.Tests.CONFIG_EXAMPLE_HOST,
                port=c.Ldap.Tests.CONFIG_LDAPS_PORT,
                use_ssl=True,
                bind_dn=c.Ldap.Tests.BIND_ADMIN_DN,
                bind_password=c.Ldap.Tests.BIND_ADMIN_PASSWORD,
            )
        )

        u.Ldap.Tests.that(cfg.Ldap.host, eq=c.Ldap.Tests.CONFIG_EXAMPLE_HOST)
        u.Ldap.Tests.that(cfg.Ldap.port, eq=c.Ldap.Tests.CONFIG_LDAPS_PORT)
        u.Ldap.Tests.that(cfg.Ldap.use_ssl, eq=True)
        u.Ldap.Tests.that(cfg.Ldap.bind_dn, eq=c.Ldap.Tests.BIND_ADMIN_DN)
        u.Ldap.Tests.that(cfg.Ldap.bind_password, eq=c.Ldap.Tests.BIND_ADMIN_PASSWORD)

    # ── Port validation (accepts in-range) ─────────────────────────────

    @pytest.mark.parametrize(c.Ldap.Tests.FIELD_PORT, c.Ldap.Tests.CONFIG_VALID_PORTS)
    def test_in_range_port_is_accepted(self, port: int) -> None:
        """Verify in range port is accepted."""
        u.Ldap.Tests.that(
            LdapTestSettings(Ldap=_LdapSettings(port=port)).Ldap.port, eq=port
        )

    # ── Port validation (rejects out-of-range) — error path ────────────

    @pytest.mark.parametrize("port", [0, -1, 65536, 70000, 999999])
    def test_out_of_range_port_is_rejected(self, port: int) -> None:
        """Verify out of range port is rejected."""
        with pytest.raises(c.ValidationError):
            LdapTestSettings(Ldap=_LdapSettings(port=port))

    # ── Host values ────────────────────────────────────────────────────

    @pytest.mark.parametrize(c.Ldap.Tests.FIELD_HOST, c.Ldap.Tests.CONFIG_HOST_CASES)
    def test_host_is_stored_verbatim(self, host: str) -> None:
        """Verify host is stored verbatim."""
        u.Ldap.Tests.that(
            LdapTestSettings(Ldap=_LdapSettings(host=host)).Ldap.host, eq=host
        )

    # ── SSL/TLS combinations ───────────────────────────────────────────

    @pytest.mark.parametrize(("ssl", "tls"), c.Ldap.Tests.CONFIG_SSL_TLS_COMBOS)
    def test_ssl_and_tls_flags_are_independent(self, *, ssl: bool, tls: bool) -> None:
        """Verify ssl and tls flags are independent."""
        cfg = LdapTestSettings(Ldap=_LdapSettings(use_ssl=ssl, use_tls=tls))

        u.Ldap.Tests.that(cfg.Ldap.use_ssl, eq=ssl)
        u.Ldap.Tests.that(cfg.Ldap.use_tls, eq=tls)

    # ── Bind credentials ───────────────────────────────────────────────

    def test_bind_credentials_are_stored(self) -> None:
        """Verify bind credentials are stored."""
        cfg = LdapTestSettings(
            Ldap=_LdapSettings(
                bind_dn=c.Ldap.Tests.BIND_ADMIN_DN,
                bind_password=c.Ldap.Tests.BIND_ADMIN_PASSWORD,
            )
        )

        u.Ldap.Tests.that(cfg.Ldap.bind_dn, eq=c.Ldap.Tests.BIND_ADMIN_DN)
        u.Ldap.Tests.that(cfg.Ldap.bind_password, eq=c.Ldap.Tests.BIND_ADMIN_PASSWORD)

    def test_empty_bind_credentials_are_preserved(self) -> None:
        """Verify empty bind credentials are preserved."""
        cfg = LdapTestSettings(Ldap=_LdapSettings(bind_dn="", bind_password=""))

        u.Ldap.Tests.that(cfg.Ldap.bind_dn, eq="")
        u.Ldap.Tests.that(cfg.Ldap.bind_password, eq="")

    # ── Serialization contract ─────────────────────────────────────────

    def test_model_dump_round_trips_custom_values(self) -> None:
        """Verify model dump round trips custom values."""
        ldap_dump = LdapTestSettings(
            Ldap=_LdapSettings(
                host=c.Ldap.Tests.CONFIG_EXAMPLE_HOST,
                port=c.Ldap.Tests.CONFIG_LDAPS_PORT,
                use_ssl=True,
            )
        ).model_dump()["Ldap"]

        u.Ldap.Tests.that(
            ldap_dump[c.Ldap.Tests.FIELD_HOST], eq=c.Ldap.Tests.CONFIG_EXAMPLE_HOST
        )
        u.Ldap.Tests.that(
            ldap_dump[c.Ldap.Tests.FIELD_PORT], eq=c.Ldap.Tests.CONFIG_LDAPS_PORT
        )
        u.Ldap.Tests.that(ldap_dump["use_ssl"], eq=True)

    def test_default_model_dump_exposes_bind_fields(self) -> None:
        """Verify default model dump exposes bind fields."""
        ldap_dump = LdapTestSettings().model_dump()["Ldap"]

        u.Ldap.Tests.that(
            ldap_dump,
            keys=[c.Ldap.Tests.FIELD_BIND_DN, c.Ldap.Tests.FIELD_BIND_PASSWORD],
        )
        u.Ldap.Tests.that(ldap_dump, lacks_keys=[c.Ldap.Tests.FIELD_BASE_DN])

    def test_json_schema_advertises_ldap_section(self) -> None:
        """Verify json schema advertises ldap section."""
        schema = LdapTestSettings.model_json_schema()

        u.Ldap.Tests.that(
            schema, keys=[c.Ldap.Tests.FIELD_PROPERTIES, c.Ldap.Tests.FIELD_TYPE]
        )
        u.Ldap.Tests.that(dict(schema[c.Ldap.Tests.FIELD_PROPERTIES]), keys=["Ldap"])

    # ── Singleton state sharing (observable contract) ──────────────────

    def test_repeated_construction_shares_settings_state(self) -> None:
        """Verify repeated construction shares settings state."""
        first = LdapTestSettings(
            Ldap=_LdapSettings(host=c.Ldap.Tests.CONFIG_FIRST_HOST, port=c.Ldap.PORT)
        )
        second = LdapTestSettings(
            Ldap=_LdapSettings(
                host=c.Ldap.Tests.CONFIG_SECOND_HOST,
                port=c.Ldap.Tests.CONFIG_LDAPS_PORT,
            )
        )

        u.Ldap.Tests.that(first.model_dump(), eq=second.model_dump())
        u.Ldap.Tests.that(first.Ldap.host, eq=second.Ldap.host)

    # ── Clone semantics ────────────────────────────────────────────────

    def test_clone_preserves_public_state(self) -> None:
        """Verify clone preserves public state."""
        original = LdapTestSettings(
            Ldap=_LdapSettings(host=c.Ldap.Tests.CONFIG_ORIGINAL_HOST, port=c.Ldap.PORT)
        )

        copied = original.clone()

        u.Ldap.Tests.that(copied, is_=LdapTestSettings, none=False)
        u.Ldap.Tests.that(copied.model_dump()["Ldap"], eq=original.model_dump()["Ldap"])

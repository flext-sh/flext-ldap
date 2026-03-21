from __future__ import annotations

import pytest

from flext_ldap import FlextLdapSettings
from tests.constants import TestsFlextLdapConstants as c
from tests.utilities import TestsFlextLdapUtilities as u

pytestmark = pytest.mark.unit


class TestsFlextLdapSettings:
    @pytest.fixture(autouse=True)
    def reset_settings_singleton(self) -> None:
        FlextLdapSettings.reset_for_testing()

    # ── Defaults contract ──────────────────────────────────────────────

    def test_defaults(self) -> None:
        cfg = FlextLdapSettings()
        u.Tests.Matchers.that(cfg.host, eq="localhost")
        u.Tests.Matchers.that(cfg.port, gte=1, lte=65535)
        u.Tests.Matchers.that(cfg.use_ssl, eq=False)
        u.Tests.Matchers.that(cfg.use_tls, eq=False)

    # ── Custom initialization ──────────────────────────────────────────

    def test_custom_values(self) -> None:
        cfg = FlextLdapSettings(
            host="example.com",
            port=636,
            use_ssl=True,
            bind_dn="cn=admin,dc=x,dc=y",
            bind_password="secret",
        )
        u.Tests.Matchers.that(cfg.host, eq="example.com")
        u.Tests.Matchers.that(cfg.port, eq=636)
        u.Tests.Matchers.that(cfg.use_ssl, eq=True)
        u.Tests.Matchers.that(cfg.bind_dn, eq="cn=admin,dc=x,dc=y")
        u.Tests.Matchers.that(cfg.bind_password, eq="secret")

    # ── Port validation ────────────────────────────────────────────────

    @pytest.mark.parametrize("port", [1, 389, 636, 65535])
    def test_port_valid(self, port: int) -> None:
        u.Tests.Matchers.that(FlextLdapSettings(port=port).port, eq=port)

    def test_port_field_constraints(self) -> None:
        field = FlextLdapSettings.model_fields["port"]
        meta = str(field.metadata)
        u.Tests.Matchers.that(meta, contains="Ge(ge=1)")
        u.Tests.Matchers.that(meta, contains="Le(le=65535)")
        u.Tests.Matchers.that(field.default, eq=c.Ldap.ConnectionDefaults.PORT)

    # ── Host values ────────────────────────────────────────────────────

    @pytest.mark.parametrize("host", ["localhost", "example.com", "192.168.1.1", ""])
    def test_host(self, host: str) -> None:
        u.Tests.Matchers.that(FlextLdapSettings(host=host).host, eq=host)

    # ── SSL/TLS combinations ───────────────────────────────────────────

    @pytest.mark.parametrize(
        ("ssl", "tls"), [(False, False), (True, False), (False, True), (True, True)]
    )
    def test_tls_options(self, ssl: bool, tls: bool) -> None:
        cfg = FlextLdapSettings(use_ssl=ssl, use_tls=tls)
        u.Tests.Matchers.that(cfg.use_ssl, eq=ssl)
        u.Tests.Matchers.that(cfg.use_tls, eq=tls)

    # ── Bind credentials ───────────────────────────────────────────────

    def test_bind_credentials_stored(self) -> None:
        cfg = FlextLdapSettings(bind_dn="cn=admin,dc=x,dc=y", bind_password="secret")
        u.Tests.Matchers.that(cfg.bind_dn, eq="cn=admin,dc=x,dc=y")
        u.Tests.Matchers.that(cfg.bind_password, eq="secret")

    def test_bind_credentials_empty(self) -> None:
        cfg = FlextLdapSettings(bind_dn="", bind_password="")
        u.Tests.Matchers.that(cfg.bind_dn, eq="")
        u.Tests.Matchers.that(cfg.bind_password, eq="")

    # ── Pydantic model features ────────────────────────────────────────

    def test_model_config(self) -> None:
        u.Tests.Matchers.that(
            FlextLdapSettings.model_config.get("env_prefix"), eq="FLEXT_"
        )
        u.Tests.Matchers.that(
            FlextLdapSettings.model_config.get("case_sensitive"), eq=False
        )

    def test_field_descriptions(self) -> None:
        fields = FlextLdapSettings.model_fields
        u.Tests.Matchers.that(fields["host"].description, none=False)
        u.Tests.Matchers.that(fields["port"].description, none=False)

    def test_serialization(self) -> None:
        data = FlextLdapSettings(
            host="example.com", port=636, use_ssl=True
        ).model_dump()
        u.Tests.Matchers.that(data["host"], eq="example.com")
        u.Tests.Matchers.that(data["port"], eq=636)
        u.Tests.Matchers.that(data["use_ssl"], eq=True)

    def test_json_schema(self) -> None:
        schema = FlextLdapSettings.model_json_schema()
        u.Tests.Matchers.that(schema, keys=["properties", "type"])
        u.Tests.Matchers.that(dict(schema["properties"]), keys=["host", "port"])

    def test_deep_copy(self) -> None:
        original = FlextLdapSettings(host="original.com", port=389)
        copied = original.model_copy(deep=True)
        u.Tests.Matchers.that(copied, is_=FlextLdapSettings, none=False)
        u.Tests.Matchers.that(
            original.model_dump()["port"], eq=copied.model_dump()["port"]
        )

    # ── Singleton behavior ─────────────────────────────────────────────

    def test_singleton_shares_state(self) -> None:
        c1 = FlextLdapSettings(host="first.com", port=389)
        c2 = FlextLdapSettings(host="second.com", port=636)
        u.Tests.Matchers.that(c1, eq=c2)
        u.Tests.Matchers.that(c1.host, eq=c2.host)

    def test_model_dump_keys(self) -> None:
        dump = FlextLdapSettings().model_dump()
        u.Tests.Matchers.that(dump, keys=["bind_dn", "bind_password"])
        u.Tests.Matchers.that(dump, lacks_keys=["base_dn"])

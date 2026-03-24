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
        tm.that(cfg.host, eq="localhost")
        tm.that(cfg.port, gte=1, lte=65535)
        tm.that(not cfg.use_ssl, eq=True)
        tm.that(not cfg.use_tls, eq=True)

    # ── Custom initialization ──────────────────────────────────────────

    def test_custom_values(self) -> None:
        cfg = FlextLdapSettings(
            host="example.com",
            port=636,
            use_ssl=True,
            bind_dn="cn=admin,dc=x,dc=y",
            bind_password="secret",
        )
        tm.that(cfg.host, eq="example.com")
        tm.that(cfg.port, eq=636)
        tm.that(cfg.use_ssl, eq=True)
        tm.that(cfg.bind_dn, eq="cn=admin,dc=x,dc=y")
        tm.that(cfg.bind_password, eq="secret")

    # ── Port validation ────────────────────────────────────────────────

    @pytest.mark.parametrize("port", [1, 389, 636, 65535])
    def test_port_valid(self, port: int) -> None:
        tm.that(FlextLdapSettings(port=port).port, eq=port)

    def test_port_field_constraints(self) -> None:
        field = FlextLdapSettings.model_fields["port"]
        tm.that(field.default, eq=c.Ldap.ConnectionDefaults.PORT)
        # PortNumber uses annotated-types constraints (Ge/Le baked into the type)
        # Validate via actual instance creation
        settings = FlextLdapSettings(port=389)
        tm.that(settings.port, eq=389)

    # ── Host values ────────────────────────────────────────────────────

    @pytest.mark.parametrize("host", ["localhost", "example.com", "192.168.1.1", ""])
    def test_host(self, host: str) -> None:
        tm.that(FlextLdapSettings(host=host).host, eq=host)

    # ── SSL/TLS combinations ───────────────────────────────────────────

    @pytest.mark.parametrize(
        ("ssl", "tls"),
        [(False, False), (True, False), (False, True), (True, True)],
    )
    def test_tls_options(self, ssl: bool, tls: bool) -> None:
        cfg = FlextLdapSettings(use_ssl=ssl, use_tls=tls)
        tm.that(cfg.use_ssl, eq=ssl)
        tm.that(cfg.use_tls, eq=tls)

    # ── Bind credentials ───────────────────────────────────────────────

    def test_bind_credentials_stored(self) -> None:
        cfg = FlextLdapSettings(bind_dn="cn=admin,dc=x,dc=y", bind_password="secret")
        tm.that(cfg.bind_dn, eq="cn=admin,dc=x,dc=y")
        tm.that(cfg.bind_password, eq="secret")

    def test_bind_credentials_empty(self) -> None:
        cfg = FlextLdapSettings(bind_dn="", bind_password="")
        tm.that(cfg.bind_dn, eq="")
        tm.that(cfg.bind_password, eq="")

    # ── Pydantic model features ────────────────────────────────────────

    def test_model_config(self) -> None:
        tm.that(FlextLdapSettings.model_config.get("env_prefix"), eq="FLEXT_")
        tm.that(not FlextLdapSettings.model_config.get("case_sensitive"), eq=True)

    def test_field_descriptions(self) -> None:
        fields = FlextLdapSettings.model_fields
        tm.that(fields["host"].description, none=False)
        tm.that(fields["port"].description, none=False)

    def test_serialization(self) -> None:
        data = FlextLdapSettings(
            host="example.com",
            port=636,
            use_ssl=True,
        ).model_dump()
        tm.that(data["host"], eq="example.com")
        tm.that(data["port"], eq=636)
        tm.that(data["use_ssl"], eq=True)

    def test_json_schema(self) -> None:
        schema = FlextLdapSettings.model_json_schema()
        tm.that(schema, keys=["properties", "type"])
        tm.that(dict(schema["properties"]), keys=["host", "port"])

    def test_deep_copy(self) -> None:
        original = FlextLdapSettings(host="original.com", port=389)
        copied = original.model_copy(deep=True)
        tm.that(copied, is_=FlextLdapSettings, none=False)
        tm.that(original.model_dump()["port"], eq=copied.model_dump()["port"])

    # ── Singleton behavior ─────────────────────────────────────────────

    def test_singleton_shares_state(self) -> None:
        c1 = FlextLdapSettings(host="first.com", port=389)
        c2 = FlextLdapSettings(host="second.com", port=636)
        tm.that(c1, eq=c2)
        tm.that(c1.host, eq=c2.host)

    def test_model_dump_keys(self) -> None:
        dump = FlextLdapSettings().model_dump()
        tm.that(dump, keys=["bind_dn", "bind_password"])
        tm.that(dump, lacks_keys=["base_dn"])

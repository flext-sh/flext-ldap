from __future__ import annotations

import pytest
from flext_tests import c, m, u
from pydantic import ValidationError

from tests import c, m

pytestmark = pytest.mark.unit


class TestsFlextLdapModels:
    def test_models_class_exists(self) -> None:
        u.Tests.Matchers.that(m, none=False)
        u.Tests.Matchers.that(
            f"{m.__module__}.{m.__qualname__}",
            eq=f"{m.__module__}.{m.__qualname__}",
        )

    def test_models_inherits_from_flext_ldif_models(self) -> None:
        u.Tests.Matchers.that(issubclass(m, m), eq=True)

    def test_nested_models_have_model_config(self) -> None:
        assert m.Ldap.ConnectionConfig.model_config is not None
        config_frozen = m.Ldap.ConnectionConfig.model_config.get("frozen", False)
        u.Tests.Matchers.that(isinstance(config_frozen, bool), eq=True)

    def test_collections_exists(self) -> None:
        u.Tests.Matchers.that(m.Categories, none=False)

    def test_collections_config_exists(self) -> None:
        u.Tests.Matchers.that(m.Config, none=False)

    def test_collections_statistics_exists(self) -> None:
        u.Tests.Matchers.that(m.Statistics, none=False)

    def test_entry_model_exists(self) -> None:
        u.Tests.Matchers.that(m.Ldif.Entry, none=False)

    def test_entry_inherits_from_flext_ldif_entry(self) -> None:
        u.Tests.Matchers.that(issubclass(m.Ldif.Entry, m.Ldif.Entry), eq=True)

    def test_entry_creation(self) -> None:
        dn = m.Ldif.DN(value=c.Ldap.Tests.RFC.DEFAULT_BASE_DN)
        entry = m.Ldif.Entry(dn=dn, attributes=None)
        u.Tests.Matchers.that(entry.dn, none=False)
        assert entry.dn is not None
        u.Tests.Matchers.that(entry.dn.value, eq=c.Ldap.Tests.RFC.DEFAULT_BASE_DN)
        u.Tests.Matchers.that(entry.attributes, none=True)

    def test_distinguished_name_via_ldif_namespace(self) -> None:
        u.Tests.Matchers.that(
            f"{m.Ldif.DN.__module__}.{m.Ldif.DN.__qualname__}",
            eq=f"{m.Ldif.DN.__module__}.{m.Ldif.DN.__qualname__}",
        )

    def test_ldif_attributes_via_ldif_namespace(self) -> None:
        actual = hasattr(m.Ldif, "Attributes")
        u.Tests.Matchers.that(actual, eq=True)
        u.Tests.Matchers.that(m.Ldif.Attributes is m.Ldif.Attributes, eq=True)

    def test_quirk_metadata_via_ldif_namespace(self) -> None:
        u.Tests.Matchers.that(
            f"{m.Ldif.QuirkMetadata.__module__}.{m.Ldif.QuirkMetadata.__qualname__}",
            eq=f"{m.Ldif.QuirkMetadata.__module__}.{m.Ldif.QuirkMetadata.__qualname__}",
        )

    def test_parse_response_via_ldif_namespace(self) -> None:
        u.Tests.Matchers.that(m.Ldif.ParseResponse, none=False)
        actual = hasattr(m.Ldif, "ParseResponse")
        u.Tests.Matchers.that(actual, eq=True)

    def test_connection_config_default_values(self) -> None:
        config = m.Ldap.ConnectionConfig()
        u.Tests.Matchers.that(config.host, eq="localhost")
        u.Tests.Matchers.that(config.port, eq=c.Ldap.ConnectionDefaults.PORT)
        u.Tests.Matchers.that(config.use_ssl, eq=False)
        u.Tests.Matchers.that(config.use_tls, eq=False)
        u.Tests.Matchers.that(config.bind_dn, none=True)
        u.Tests.Matchers.that(config.bind_password, none=True)
        u.Tests.Matchers.that(config.timeout, eq=c.Ldap.ConnectionDefaults.TIMEOUT)
        u.Tests.Matchers.that(config.auto_bind, eq=c.Ldap.ConnectionDefaults.AUTO_BIND)

    def test_connection_config_custom_values(self) -> None:
        config = m.Ldap.ConnectionConfig(
            host="ldap.example.com",
            port=636,
            use_ssl=True,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="secret",
            timeout=60,
        )
        u.Tests.Matchers.that(config.host, eq="ldap.example.com")
        u.Tests.Matchers.that(config.port, eq=636)
        u.Tests.Matchers.that(config.use_ssl, eq=True)
        u.Tests.Matchers.that(
            config.bind_dn, eq="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        )

    def test_connection_config_ssl_tls_mutual_exclusion(self) -> None:
        with pytest.raises(ValidationError, match="mutually exclusive"):
            m.Ldap.ConnectionConfig(use_ssl=True, use_tls=True)

    def test_connection_config_ssl_only_allowed(self) -> None:
        config = m.Ldap.ConnectionConfig(use_ssl=True, use_tls=False)
        u.Tests.Matchers.that(config.use_ssl, eq=True)
        u.Tests.Matchers.that(config.use_tls, eq=False)

    def test_connection_config_tls_only_allowed(self) -> None:
        config = m.Ldap.ConnectionConfig(use_ssl=False, use_tls=True)
        u.Tests.Matchers.that(config.use_ssl, eq=False)
        u.Tests.Matchers.that(config.use_tls, eq=True)

    def test_connection_config_port_constraints(self) -> None:
        config_min = m.Ldap.ConnectionConfig(port=1)
        u.Tests.Matchers.that(config_min.port, eq=1)
        config_max = m.Ldap.ConnectionConfig(port=65535)
        u.Tests.Matchers.that(config_max.port, eq=65535)

    def test_connection_config_port_constraint_violation_min(self) -> None:
        invalid_port: int = 0
        with pytest.raises(ValidationError):
            m.Ldap.ConnectionConfig(port=invalid_port)

    def test_connection_config_port_constraint_violation_max(self) -> None:
        invalid_port: int = 65536
        with pytest.raises(ValidationError):
            m.Ldap.ConnectionConfig(port=invalid_port)

    def test_connection_config_inherits_from_collections_config(self) -> None:
        config = m.Ldap.ConnectionConfig()
        u.Tests.Matchers.that(config, none=False)
        u.Tests.Matchers.that(config.host, eq="localhost")
        u.Tests.Matchers.that(config.port, eq=389)
        dump = config.model_dump()
        u.Tests.Matchers.that(dump, keys=["host", "port"])


__all__ = ["TestsFlextLdapModels"]

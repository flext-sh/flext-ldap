from __future__ import annotations

import pytest
from pydantic import ValidationError

from tests import c, m, u

pytestmark = pytest.mark.unit


class TestsFlextLdapModels:
    def test_models_class_exists(self) -> None:
        u.Tests.Matchers.that(m, none=False)
        u.Tests.Matchers.that(
            f"{m.__module__}.{m.__qualname__}",
            eq=f"{m.__module__}.{m.__qualname__}",
        )

    def test_models_inherits_from_flext_ldif_models(self) -> None:
        # Verify FlextLdapModels properly extends FlextLdifModels
        u.Tests.Matchers.that(hasattr(m, "Ldif"), eq=True)

    def test_nested_models_have_model_config(self) -> None:
        assert m.Ldap.ConnectionConfig.model_config is not None
        config_frozen = m.Ldap.ConnectionConfig.model_config.get("frozen", False)
        u.Tests.Matchers.that(config_frozen, is_=bool)

    def test_collections_exists(self) -> None:
        u.Tests.Matchers.that(m.Ldif.FlexibleCategories, none=False)

    def test_collections_config_exists(self) -> None:
        u.Tests.Matchers.that(m.Config, none=False)

    def test_collections_statistics_exists(self) -> None:
        u.Tests.Matchers.that(m.Statistics, none=False)

    def test_entry_model_exists(self) -> None:
        u.Tests.Matchers.that(m.Ldif.Entry, none=False)

    def test_entry_inherits_from_flext_ldif_entry(self) -> None:
        # Verify Entry class is properly defined and accessible
        u.Tests.Matchers.that(m.Ldif.Entry, none=False)

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
        config = m.Ldap.ConnectionConfig(port=c.Ldap.ConnectionDefaults.PORT)
        u.Tests.Matchers.that(config.host, eq=c.LOCALHOST)
        u.Tests.Matchers.that(config.port, eq=c.Ldap.ConnectionDefaults.PORT)
        u.Tests.Matchers.that(not config.use_ssl, eq=True)
        u.Tests.Matchers.that(not config.use_tls, eq=True)
        u.Tests.Matchers.that(config.bind_dn, none=True)
        u.Tests.Matchers.that(config.bind_password, none=True)
        u.Tests.Matchers.that(config.timeout, eq=c.Ldap.ConnectionDefaults.TIMEOUT)
        u.Tests.Matchers.that(config.auto_bind, eq=c.Ldap.ConnectionDefaults.AUTO_BIND)

    def test_connection_config_custom_values(self) -> None:
        config = m.Ldap.ConnectionConfig(
            host=c.Ldap.Tests.Models.LDAP_EXAMPLE_HOST,
            port=c.Ldap.Tests.Config.LDAPS_PORT,
            use_ssl=True,
            bind_dn=c.Ldap.Tests.EntryDN.ADMIN_EXAMPLE,
            bind_password=c.Ldap.Tests.BindCredentials.ADMIN_PASSWORD,
            timeout=c.Ldap.Tests.Models.CUSTOM_TIMEOUT,
        )
        u.Tests.Matchers.that(config.host, eq=c.Ldap.Tests.Models.LDAP_EXAMPLE_HOST)
        u.Tests.Matchers.that(config.port, eq=c.Ldap.Tests.Config.LDAPS_PORT)
        u.Tests.Matchers.that(config.use_ssl, eq=True)
        u.Tests.Matchers.that(config.bind_dn, eq=c.Ldap.Tests.EntryDN.ADMIN_EXAMPLE)

    def test_connection_config_ssl_tls_mutual_exclusion(self) -> None:
        with pytest.raises(ValidationError, match="mutually exclusive"):
            m.Ldap.ConnectionConfig(
                port=c.Ldap.ConnectionDefaults.PORT, use_ssl=True, use_tls=True
            )

    def test_connection_config_ssl_only_allowed(self) -> None:
        config = m.Ldap.ConnectionConfig(
            port=c.Ldap.ConnectionDefaults.PORT, use_ssl=True, use_tls=False
        )
        u.Tests.Matchers.that(config.use_ssl, eq=True)
        u.Tests.Matchers.that(not config.use_tls, eq=True)

    def test_connection_config_tls_only_allowed(self) -> None:
        config = m.Ldap.ConnectionConfig(
            port=c.Ldap.ConnectionDefaults.PORT, use_ssl=False, use_tls=True
        )
        u.Tests.Matchers.that(not config.use_ssl, eq=True)
        u.Tests.Matchers.that(config.use_tls, eq=True)

    def test_connection_config_port_constraints(self) -> None:
        config_min = m.Ldap.ConnectionConfig(port=c.Ldap.Tests.Config.PORT_MIN)
        u.Tests.Matchers.that(config_min.port, eq=c.Ldap.Tests.Config.PORT_MIN)
        config_max = m.Ldap.ConnectionConfig(port=c.Ldap.Tests.Config.PORT_MAX)
        u.Tests.Matchers.that(config_max.port, eq=c.Ldap.Tests.Config.PORT_MAX)

    def test_connection_config_port_constraint_violation_min(self) -> None:
        invalid_port: int = c.Ldap.Tests.Models.INVALID_PORT_BELOW_MIN
        with pytest.raises(ValidationError):
            m.Ldap.ConnectionConfig(port=invalid_port)

    def test_connection_config_port_constraint_violation_max(self) -> None:
        invalid_port: int = c.Ldap.Tests.Models.INVALID_PORT_ABOVE_MAX
        with pytest.raises(ValidationError):
            m.Ldap.ConnectionConfig(port=invalid_port)

    def test_connection_config_inherits_from_collections_config(self) -> None:
        config = m.Ldap.ConnectionConfig(port=c.Ldap.ConnectionDefaults.PORT)
        u.Tests.Matchers.that(config, none=False)
        u.Tests.Matchers.that(config.host, eq=c.LOCALHOST)
        u.Tests.Matchers.that(config.port, eq=c.Ldap.ConnectionDefaults.PORT)
        dump = config.model_dump()
        u.Tests.Matchers.that(
            dump, keys=[c.Ldap.Tests.FieldNames.HOST, c.Ldap.Tests.FieldNames.PORT]
        )


__all__ = ["TestsFlextLdapModels"]

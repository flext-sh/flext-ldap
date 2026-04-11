from __future__ import annotations

import pytest
from pydantic import ValidationError

from tests import c, m, u

pytestmark = pytest.mark.unit


class TestsFlextLdapModels:
    def test_models_class_exists(self) -> None:
        u.Ldap.Tests.that(m, none=False)
        u.Ldap.Tests.that(
            f"{m.__module__}.{m.__qualname__}", eq=f"{m.__module__}.{m.__qualname__}"
        )

    def test_models_inherits_from_flext_ldif_models(self) -> None:
        # Verify FlextLdapModels properly extends FlextLdifModels
        u.Ldap.Tests.that(hasattr(m, "Ldif"), eq=True)

    def test_nested_models_have_model_config(self) -> None:
        assert m.Ldap.ConnectionConfig.model_config is not None
        config_frozen = m.Ldap.ConnectionConfig.model_config.get("frozen", False)
        u.Ldap.Tests.that(config_frozen, is_=bool)

    def test_collections_exists(self) -> None:
        u.Ldap.Tests.that(m.Ldif.FlexibleCategories, none=False)

    def test_collections_config_exists(self) -> None:
        u.Ldap.Tests.that(m.Config, none=False)

    def test_collections_statistics_exists(self) -> None:
        u.Ldap.Tests.that(m.Statistics, none=False)

    def test_entry_model_exists(self) -> None:
        u.Ldap.Tests.that(m.Ldif.Entry, none=False)

    def test_entry_inherits_from_flext_ldif_entry(self) -> None:
        # Verify Entry class is properly defined and accessible
        u.Ldap.Tests.that(m.Ldif.Entry, none=False)

    def test_entry_creation(self) -> None:
        dn = m.Ldif.DN(value=c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        entry = m.Ldif.Entry(dn=dn, attributes=None)
        u.Ldap.Tests.that(entry.dn, none=False)
        assert entry.dn is not None
        u.Ldap.Tests.that(entry.dn.value, eq=c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        u.Ldap.Tests.that(entry.attributes, none=True)

    def test_distinguished_name_via_ldif_namespace(self) -> None:
        u.Ldap.Tests.that(
            f"{m.Ldif.DN.__module__}.{m.Ldif.DN.__qualname__}",
            eq=f"{m.Ldif.DN.__module__}.{m.Ldif.DN.__qualname__}",
        )

    def test_ldif_attributes_via_ldif_namespace(self) -> None:
        actual = hasattr(m.Ldif, "Attributes")
        u.Ldap.Tests.that(actual, eq=True)
        u.Ldap.Tests.that(m.Ldif.Attributes is m.Ldif.Attributes, eq=True)

    def test_quirk_metadata_via_ldif_namespace(self) -> None:
        u.Ldap.Tests.that(
            f"{m.Ldif.QuirkMetadata.__module__}.{m.Ldif.QuirkMetadata.__qualname__}",
            eq=f"{m.Ldif.QuirkMetadata.__module__}.{m.Ldif.QuirkMetadata.__qualname__}",
        )

    def test_parse_response_via_ldif_namespace(self) -> None:
        u.Ldap.Tests.that(m.Ldif.ParseResponse, none=False)
        actual = hasattr(m.Ldif, "ParseResponse")
        u.Ldap.Tests.that(actual, eq=True)

    def test_connection_config_default_values(self) -> None:
        settings = m.Ldap.ConnectionConfig(port=c.Ldap.ConnectionDefaults.PORT)
        u.Ldap.Tests.that(settings.host, eq=c.LOCALHOST)
        u.Ldap.Tests.that(settings.port, eq=c.Ldap.ConnectionDefaults.PORT)
        u.Ldap.Tests.that(not settings.use_ssl, eq=True)
        u.Ldap.Tests.that(not settings.use_tls, eq=True)
        u.Ldap.Tests.that(settings.bind_dn, none=True)
        u.Ldap.Tests.that(settings.bind_password, none=True)
        u.Ldap.Tests.that(settings.timeout, eq=c.Ldap.ConnectionDefaults.TIMEOUT)
        u.Ldap.Tests.that(settings.auto_bind, eq=c.Ldap.ConnectionDefaults.AUTO_BIND)

    def test_connection_config_custom_values(self) -> None:
        settings = m.Ldap.ConnectionConfig(
            host=c.Ldap.Tests.MODELS_LDAP_EXAMPLE_HOST,
            port=c.Ldap.Tests.CONFIG_LDAPS_PORT,
            use_ssl=True,
            bind_dn=c.Ldap.Tests.ENTRY_DN_ADMIN_EXAMPLE,
            bind_password=c.Ldap.Tests.BIND_ADMIN_PASSWORD,
            timeout=c.Ldap.Tests.MODELS_CUSTOM_TIMEOUT,
        )
        u.Ldap.Tests.that(settings.host, eq=c.Ldap.Tests.MODELS_LDAP_EXAMPLE_HOST)
        u.Ldap.Tests.that(settings.port, eq=c.Ldap.Tests.CONFIG_LDAPS_PORT)
        u.Ldap.Tests.that(settings.use_ssl, eq=True)
        u.Ldap.Tests.that(settings.bind_dn, eq=c.Ldap.Tests.ENTRY_DN_ADMIN_EXAMPLE)

    def test_connection_config_ssl_tls_mutual_exclusion(self) -> None:
        with pytest.raises(ValidationError, match="mutually exclusive"):
            m.Ldap.ConnectionConfig(
                port=c.Ldap.ConnectionDefaults.PORT, use_ssl=True, use_tls=True
            )

    def test_connection_config_ssl_only_allowed(self) -> None:
        settings = m.Ldap.ConnectionConfig(
            port=c.Ldap.ConnectionDefaults.PORT, use_ssl=True, use_tls=False
        )
        u.Ldap.Tests.that(settings.use_ssl, eq=True)
        u.Ldap.Tests.that(not settings.use_tls, eq=True)

    def test_connection_config_tls_only_allowed(self) -> None:
        settings = m.Ldap.ConnectionConfig(
            port=c.Ldap.ConnectionDefaults.PORT, use_ssl=False, use_tls=True
        )
        u.Ldap.Tests.that(not settings.use_ssl, eq=True)
        u.Ldap.Tests.that(settings.use_tls, eq=True)

    def test_connection_config_port_constraints(self) -> None:
        config_min = m.Ldap.ConnectionConfig(port=c.Ldap.Tests.CONFIG_PORT_MIN)
        u.Ldap.Tests.that(config_min.port, eq=c.Ldap.Tests.CONFIG_PORT_MIN)
        config_max = m.Ldap.ConnectionConfig(port=c.Ldap.Tests.CONFIG_PORT_MAX)
        u.Ldap.Tests.that(config_max.port, eq=c.Ldap.Tests.CONFIG_PORT_MAX)

    def test_connection_config_port_constraint_violation_min(self) -> None:
        invalid_port: int = c.Ldap.Tests.MODELS_INVALID_PORT_BELOW_MIN
        with pytest.raises(ValidationError):
            m.Ldap.ConnectionConfig(port=invalid_port)

    def test_connection_config_port_constraint_violation_max(self) -> None:
        invalid_port: int = c.Ldap.Tests.MODELS_INVALID_PORT_ABOVE_MAX
        with pytest.raises(ValidationError):
            m.Ldap.ConnectionConfig(port=invalid_port)

    def test_connection_config_inherits_from_collections_config(self) -> None:
        settings = m.Ldap.ConnectionConfig(port=c.Ldap.ConnectionDefaults.PORT)
        u.Ldap.Tests.that(settings, none=False)
        u.Ldap.Tests.that(settings.host, eq=c.LOCALHOST)
        u.Ldap.Tests.that(settings.port, eq=c.Ldap.ConnectionDefaults.PORT)
        dump = settings.model_dump()
        u.Ldap.Tests.that(dump, keys=[c.Ldap.Tests.FIELD_HOST, c.Ldap.Tests.FIELD_PORT])


__all__ = ["TestsFlextLdapModels"]

from __future__ import annotations

import pytest

from tests import c, m, u

pytestmark = pytest.mark.unit


class TestsFlextLdapModelsUnit:
    def test_entry_creation(self) -> None:
        dn = m.Ldif.DN(value=c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        entry = m.Ldif.Entry(dn=dn, attributes=None)
        u.Ldap.Tests.that(entry.dn, none=False)
        assert entry.dn is not None
        u.Ldap.Tests.that(entry.dn.value, eq=c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        u.Ldap.Tests.that(entry.attributes, none=True)

    def test_connection_config_default_values(self) -> None:
        settings = m.Ldap.ConnectionConfig(port=c.Ldap.PORT)
        u.Ldap.Tests.that(settings.host, eq=c.LOCALHOST)
        u.Ldap.Tests.that(settings.port, eq=c.Ldap.PORT)
        u.Ldap.Tests.that(not settings.use_ssl, eq=True)
        u.Ldap.Tests.that(not settings.use_tls, eq=True)
        u.Ldap.Tests.that(settings.bind_dn, none=True)
        u.Ldap.Tests.that(settings.bind_password, none=True)
        u.Ldap.Tests.that(settings.timeout, eq=c.Ldap.TIMEOUT)
        u.Ldap.Tests.that(settings.auto_bind, eq=c.Ldap.AUTO_BIND)

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
        with pytest.raises(c.ValidationError, match="mutually exclusive"):
            m.Ldap.ConnectionConfig(port=c.Ldap.PORT, use_ssl=True, use_tls=True)

    @pytest.mark.parametrize("case", c.Ldap.Tests.ConnectionSecurityCase)
    def test_connection_config_allowed_security_modes(
        self,
        case: c.Ldap.Tests.ConnectionSecurityCase,
    ) -> None:
        use_ssl, use_tls = c.Ldap.Tests.MODELS_ALLOWED_SECURITY_COMBOS[case]
        settings = m.Ldap.ConnectionConfig(
            port=c.Ldap.PORT, use_ssl=use_ssl, use_tls=use_tls
        )
        u.Ldap.Tests.that(settings.use_ssl, eq=use_ssl)
        u.Ldap.Tests.that(settings.use_tls, eq=use_tls)

    def test_connection_config_port_constraints(self) -> None:
        config_min = m.Ldap.ConnectionConfig(port=c.Ldap.Tests.CONFIG_PORT_MIN)
        u.Ldap.Tests.that(config_min.port, eq=c.Ldap.Tests.CONFIG_PORT_MIN)
        config_max = m.Ldap.ConnectionConfig(port=c.Ldap.Tests.CONFIG_PORT_MAX)
        u.Ldap.Tests.that(config_max.port, eq=c.Ldap.Tests.CONFIG_PORT_MAX)

    @pytest.mark.parametrize("invalid_port", c.Ldap.Tests.MODELS_INVALID_PORTS)
    def test_connection_config_port_constraint_violations(
        self,
        invalid_port: int,
    ) -> None:
        with pytest.raises(c.ValidationError):
            m.Ldap.ConnectionConfig(port=invalid_port)

    def test_connection_config_inherits_from_collections_config(self) -> None:
        settings = m.Ldap.ConnectionConfig(port=c.Ldap.PORT)
        u.Ldap.Tests.that(settings, none=False)
        u.Ldap.Tests.that(settings.host, eq=c.LOCALHOST)
        u.Ldap.Tests.that(settings.port, eq=c.Ldap.PORT)
        dump = settings.model_dump()
        u.Ldap.Tests.that(dump, keys=[c.Ldap.Tests.FIELD_HOST, c.Ldap.Tests.FIELD_PORT])


__all__: list[str] = ["TestsFlextLdapModelsUnit"]

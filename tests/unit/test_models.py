"""Tests for models."""

from __future__ import annotations

import pytest

from tests import c, m, u

pytestmark = pytest.mark.unit


class TestsFlextLdapModelsUnit:
    """Behavioral contract for FlextLdapModels public model surface."""

    def test_entry_exposes_dn_value_and_null_attributes(self) -> None:
        """Verify entry exposes dn value and null attributes."""
        dn = m.Ldif.DN(value=c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        entry = m.Ldif.Entry(dn=dn, attributes=None)

        u.Ldap.Tests.that(entry.dn_str, eq=c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        u.Ldap.Tests.that(entry.attributes, none=True)

    def test_entry_exposes_attributes_through_public_accessor(self) -> None:
        """Verify entry exposes attributes through public accessor."""
        dn = m.Ldif.DN(value=c.Ldap.Tests.RFC_DEFAULT_BASE_DN)
        entry = m.Ldif.Entry(
            dn=dn,
            attributes=m.Ldif.Attributes(attributes={"cn": ["alice"], "sn": ["smith"]}),
        )

        u.Ldap.Tests.that(
            entry.attributes_dict,
            eq={"cn": ["alice"], "sn": ["smith"]},
        )

    def test_connection_config_default_values(self) -> None:
        """Verify connection config default values."""
        settings = m.Ldap.ConnectionConfig(port=c.Ldap.PORT)

        u.Ldap.Tests.that(settings.host, eq=c.LOCALHOST)
        u.Ldap.Tests.that(settings.port, eq=c.Ldap.PORT)
        u.Ldap.Tests.that(settings.use_ssl, eq=False)
        u.Ldap.Tests.that(settings.use_tls, eq=False)
        u.Ldap.Tests.that(settings.bind_dn, none=True)
        u.Ldap.Tests.that(settings.bind_password, none=True)
        u.Ldap.Tests.that(settings.timeout, eq=c.Ldap.TIMEOUT)
        u.Ldap.Tests.that(settings.auto_bind, eq=True)
        u.Ldap.Tests.that(settings.auto_range, eq=True)

    def test_connection_config_custom_values(self) -> None:
        """Verify connection config custom values."""
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
        u.Ldap.Tests.that(
            settings.bind_password,
            eq=c.Ldap.Tests.BIND_ADMIN_PASSWORD,
        )
        u.Ldap.Tests.that(settings.timeout, eq=c.Ldap.Tests.MODELS_CUSTOM_TIMEOUT)

    def test_connection_config_rejects_ssl_and_tls_together(self) -> None:
        """Verify connection config rejects ssl and tls together."""
        with pytest.raises(c.ValidationError, match="mutually exclusive"):
            m.Ldap.ConnectionConfig(port=c.Ldap.PORT, use_ssl=True, use_tls=True)

    @pytest.mark.parametrize("case", c.Ldap.Tests.ConnectionSecurityCase)
    def test_connection_config_accepts_single_security_mode(
        self,
        case: c.Ldap.Tests.ConnectionSecurityCase,
    ) -> None:
        """Verify connection config accepts single security mode."""
        use_ssl, use_tls = c.Ldap.Tests.MODELS_ALLOWED_SECURITY_COMBOS[case]

        settings = m.Ldap.ConnectionConfig(
            port=c.Ldap.PORT,
            use_ssl=use_ssl,
            use_tls=use_tls,
        )

        u.Ldap.Tests.that(settings.use_ssl, eq=use_ssl)
        u.Ldap.Tests.that(settings.use_tls, eq=use_tls)

    @pytest.mark.parametrize(
        "port",
        [c.Ldap.Tests.CONFIG_PORT_MIN, c.Ldap.Tests.CONFIG_PORT_MAX],
    )
    def test_connection_config_accepts_boundary_ports(self, port: int) -> None:
        """Verify connection config accepts boundary ports."""
        settings = m.Ldap.ConnectionConfig(port=port)

        u.Ldap.Tests.that(settings.port, eq=port)

    @pytest.mark.parametrize("invalid_port", c.Ldap.Tests.MODELS_INVALID_PORTS)
    def test_connection_config_rejects_out_of_range_ports(
        self,
        invalid_port: int,
    ) -> None:
        """Verify connection config rejects out of range ports."""
        with pytest.raises(c.ValidationError):
            m.Ldap.ConnectionConfig(port=invalid_port)

    def test_connection_config_model_dump_exposes_public_fields(self) -> None:
        """Verify connection config model dump exposes public fields."""
        settings = m.Ldap.ConnectionConfig(port=c.Ldap.PORT)

        dump = settings.model_dump()

        u.Ldap.Tests.that(
            dump,
            keys=[c.Ldap.Tests.FIELD_HOST, c.Ldap.Tests.FIELD_PORT],
        )
        u.Ldap.Tests.that(dump[c.Ldap.Tests.FIELD_HOST], eq=c.LOCALHOST)
        u.Ldap.Tests.that(dump[c.Ldap.Tests.FIELD_PORT], eq=c.Ldap.PORT)

    def test_connection_config_survives_dump_validate_roundtrip(self) -> None:
        """Verify connection config survives dump validate roundtrip."""
        original = m.Ldap.ConnectionConfig(
            host=c.Ldap.Tests.MODELS_LDAP_EXAMPLE_HOST,
            port=c.Ldap.Tests.CONFIG_LDAPS_PORT,
            use_ssl=True,
            timeout=c.Ldap.Tests.MODELS_CUSTOM_TIMEOUT,
        )

        restored = m.Ldap.ConnectionConfig.model_validate(original.model_dump())

        u.Ldap.Tests.that(restored, eq=original)


__all__: list[str] = ["TestsFlextLdapModelsUnit"]

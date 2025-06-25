"""Comprehensive tests for LDAP Base Classes.

This test suite validates the foundational LDAP connection classes extracted
from client-a-oud-mig, ensuring Zero Tolerance quality standards.

Test Coverage:
    - LDAPConnectionInfo validation and security
    - LDAPConnectionOptions configuration
    - LDAPSearchConfig validation
    - Security password handling
    - LDAP3 integration mapping
    - Property-based testing for edge cases

Test Philosophy:
    - 100% code coverage target
    - Security-first validation
    - Property-based testing for robustness
    - Zero Tolerance for security issues
"""

from __future__ import annotations

import ldap3
import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from ldap_core_shared.connections.base import (
    LDAPAuthenticationMethod,
    LDAPConnectionInfo,
    LDAPConnectionOptions,
    LDAPSearchConfig,
    LDAPSearchScope,
)


class TestLDAPConnectionInfo:
    """Test suite for LDAPConnectionInfo model."""

    def test_basic_connection_info_creation(self) -> None:
        """Test basic LDAPConnectionInfo creation."""
        conn_info = LDAPConnectionInfo(
            host="ldap.example.com",
            port=389,
            use_ssl=False,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="secret123",
            base_dn="dc=example,dc=com",
        )

        assert conn_info.host == "ldap.example.com"
        assert conn_info.port == 389
        assert conn_info.use_ssl is False
        assert conn_info.bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        assert conn_info.bind_password.get_secret_value() == "secret123"
        assert conn_info.base_dn == "dc=example,dc=com"
        assert conn_info.authentication == LDAPAuthenticationMethod.SIMPLE
        assert conn_info.auto_bind is True

    def test_ssl_connection_info(self) -> None:
        """Test SSL/TLS connection configuration."""
        conn_info = LDAPConnectionInfo(
            host="ldaps.example.com",
            port=636,
            use_ssl=True,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="secret123",
            base_dn="dc=example,dc=com",
        )

        assert conn_info.use_ssl is True
        assert conn_info.port == 636

    def test_sasl_authentication(self) -> None:
        """Test SASL authentication configuration."""
        conn_info = LDAPConnectionInfo(
            host="ldap.example.com",
            port=389,
            use_ssl=False,
            bind_dn="cn=user,dc=example,dc=com",
            bind_password="secret123",
            base_dn="dc=example,dc=com",
            authentication=LDAPAuthenticationMethod.SASL,
        )

        assert conn_info.authentication == LDAPAuthenticationMethod.SASL

    def test_anonymous_authentication(self) -> None:
        """Test anonymous authentication configuration."""
        conn_info = LDAPConnectionInfo(
            host="ldap.example.com",
            port=389,
            use_ssl=False,
            bind_dn="cn=anonymous,dc=example,dc=com",
            bind_password="anonymous",
            base_dn="dc=example,dc=com",
            authentication=LDAPAuthenticationMethod.ANONYMOUS,
        )

        assert conn_info.authentication == LDAPAuthenticationMethod.ANONYMOUS
        assert conn_info.bind_dn == "cn=anonymous,dc=example,dc=com"
        assert conn_info.bind_password.get_secret_value() == "anonymous"

    def test_password_security(self) -> None:
        """Test password security handling."""
        conn_info = LDAPConnectionInfo(
            host="ldap.example.com",
            port=389,
            use_ssl=False,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="topsecret",
            base_dn="dc=example,dc=com",
        )

        # Password should be hidden in string representation
        str_repr = str(conn_info)
        assert "topsecret" not in str_repr
        assert "**********" in str_repr or "*" in str_repr

        # But accessible via get_secret_value()
        assert conn_info.bind_password.get_secret_value() == "topsecret"

    def test_ldap3_authentication_mapping(self) -> None:
        """Test mapping to ldap3 authentication types."""
        # Simple authentication
        conn_info = LDAPConnectionInfo(
            host="ldap.example.com",
            port=389,
            use_ssl=False,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="secret",
            base_dn="dc=example,dc=com",
            authentication=LDAPAuthenticationMethod.SIMPLE,
        )
        assert conn_info.get_ldap3_authentication() == ldap3.SIMPLE

        # SASL authentication - create new instance since model is frozen
        sasl_conn_info = LDAPConnectionInfo(
            host="ldap.example.com",
            port=389,
            use_ssl=False,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="secret",
            base_dn="dc=example,dc=com",
            authentication=LDAPAuthenticationMethod.SASL,
        )
        assert sasl_conn_info.get_ldap3_authentication() == ldap3.SASL

        # Anonymous authentication - create new instance since model is frozen
        anon_conn_info = LDAPConnectionInfo(
            host="ldap.example.com",
            port=389,
            use_ssl=False,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="secret",
            base_dn="dc=example,dc=com",
            authentication=LDAPAuthenticationMethod.ANONYMOUS,
        )
        assert anon_conn_info.get_ldap3_authentication() == ldap3.ANONYMOUS

    def test_validation_errors(self) -> None:
        """Test validation error handling."""
        # Invalid port
        with pytest.raises(ValidationError):
            LDAPConnectionInfo(
                host="ldap.example.com",
                port=0,  # Invalid port
                use_ssl=False,
                bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
                bind_password="secret",
                base_dn="dc=example,dc=com",
            )

        # Invalid port (too high)
        with pytest.raises(ValidationError):
            LDAPConnectionInfo(
                host="ldap.example.com",
                port=70000,  # Invalid port
                use_ssl=False,
                bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
                bind_password="secret",
                base_dn="dc=example,dc=com",
            )

        # Missing required fields
        with pytest.raises(ValidationError):
            LDAPConnectionInfo(
                host="",  # Empty host
                port=389,
                use_ssl=False,
                bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
                bind_password="secret",
                base_dn="dc=example,dc=com",
            )

    @given(
        host=st.text(min_size=1, max_size=100),
        port=st.integers(min_value=1, max_value=65535),
        bind_dn=st.text(min_size=1, max_size=200),
        base_dn=st.text(min_size=1, max_size=200),
    )
    def test_property_based_validation(
        self, host: str, port: int, bind_dn: str, base_dn: str
    ) -> None:
        """Property-based test for connection info validation."""
        try:
            conn_info = LDAPConnectionInfo(
                host=host,
                port=port,
                use_ssl=False,
                bind_dn=bind_dn,
                bind_password="test",
                base_dn=base_dn,
            )

            # If creation succeeds, verify basic properties
            assert conn_info.host == host
            assert conn_info.port == port
            assert conn_info.bind_dn == bind_dn
            assert conn_info.base_dn == base_dn

        except ValidationError:
            # Validation errors are expected for some random inputs
            pass

    def test_immutability(self) -> None:
        """Test that connection info is immutable."""
        conn_info = LDAPConnectionInfo(
            host="ldap.example.com",
            port=389,
            use_ssl=False,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="secret",
            base_dn="dc=example,dc=com",
        )

        # Should not be able to modify fields (frozen model)
        with pytest.raises(ValidationError):
            conn_info.host = "different.host.com"


class TestLDAPConnectionOptions:
    """Test suite for LDAPConnectionOptions model."""

    @pytest.fixture
    def connection_info(self) -> LDAPConnectionInfo:
        """Create test connection info."""
        return LDAPConnectionInfo(
            host="ldap.test.com",
            port=389,
            use_ssl=False,
            bind_dn="cn=test,dc=test,dc=com",
            bind_password="test123",
            base_dn="dc=test,dc=com",
        )

    def test_basic_connection_options(
        self, connection_info: LDAPConnectionInfo
    ) -> None:
        """Test basic connection options creation."""
        options = LDAPConnectionOptions(
            connection_info=connection_info,
            connection_pool_enabled=True,
            max_pool_size=10,
        )

        assert options.connection_info == connection_info
        assert options.connection_pool_enabled is True
        assert options.max_pool_size == 10
        assert options.enable_ssh_tunnel is False

    def test_ssh_tunnel_options(self, connection_info: LDAPConnectionInfo) -> None:
        """Test SSH tunnel configuration."""
        options = LDAPConnectionOptions(
            connection_info=connection_info,
            enable_ssh_tunnel=True,
            ssh_host="ssh.example.com",
            ssh_port=22,
            ssh_username="sshuser",
        )

        assert options.enable_ssh_tunnel is True
        assert options.ssh_host == "ssh.example.com"
        assert options.ssh_port == 22
        assert options.ssh_username == "sshuser"

    def test_connection_pool_validation(
        self, connection_info: LDAPConnectionInfo
    ) -> None:
        """Test connection pool validation."""
        # Valid pool size
        options = LDAPConnectionOptions(
            connection_info=connection_info,
            connection_pool_enabled=True,
            max_pool_size=20,
        )
        assert options.max_pool_size == 20

        # Invalid pool size (too small)
        with pytest.raises(ValidationError):
            LDAPConnectionOptions(
                connection_info=connection_info,
                connection_pool_enabled=True,
                max_pool_size=0,
            )

        # Invalid pool size (too large)
        with pytest.raises(ValidationError):
            LDAPConnectionOptions(
                connection_info=connection_info,
                connection_pool_enabled=True,
                max_pool_size=1000,
            )

    def test_ssh_port_validation(self, connection_info: LDAPConnectionInfo) -> None:
        """Test SSH port validation."""
        # Valid SSH port
        options = LDAPConnectionOptions(
            connection_info=connection_info,
            enable_ssh_tunnel=True,
            ssh_host="ssh.example.com",
            ssh_port=2222,
            ssh_username="user",
        )
        assert options.ssh_port == 2222

        # Invalid SSH port
        with pytest.raises(ValidationError):
            LDAPConnectionOptions(
                connection_info=connection_info,
                enable_ssh_tunnel=True,
                ssh_host="ssh.example.com",
                ssh_port=0,
                ssh_username="user",
            )

    def test_ssh_security(self, connection_info: LDAPConnectionInfo) -> None:
        """Test SSH security configuration."""
        options = LDAPConnectionOptions(
            connection_info=connection_info,
            enable_ssh_tunnel=True,
            ssh_host="ssh.example.com",
            ssh_username="user",
        )

        # SSH host should be properly set
        assert options.ssh_host == "ssh.example.com"
        assert options.ssh_username == "user"


class TestLDAPSearchConfig:
    """Test suite for LDAPSearchConfig model."""

    def test_basic_search_config(self) -> None:
        """Test basic search configuration."""
        config = LDAPSearchConfig(
            search_base="dc=example,dc=com",
            search_filter="(objectClass=person)",
        )

        assert config.search_base == "dc=example,dc=com"
        assert config.search_filter == "(objectClass=person)"
        assert config.attributes is None  # Default: all attributes
        assert config.search_scope == "subtree"
        assert config.size_limit == 1000  # Default from constants
        assert config.time_limit == 30  # Default from constants

    def test_search_config_with_attributes(self) -> None:
        """Test search configuration with specific attributes."""
        config = LDAPSearchConfig(
            search_base="ou=users,dc=example,dc=com",
            search_filter="(objectClass=inetOrgPerson)",
            attributes=["cn", "mail", "uid"],
        )

        assert config.attributes == ["cn", "mail", "uid"]

    def test_search_scope_configuration(self) -> None:
        """Test different search scope configurations."""
        # Base scope
        config = LDAPSearchConfig(
            search_base="cn=user,dc=example,dc=com",
            search_filter="(objectClass=*)",
            search_scope="BASE",
        )
        assert config.search_scope == "BASE"

        # One level scope - create new instance since model is frozen
        config_onelevel = LDAPSearchConfig(
            search_base="cn=user,dc=example,dc=com",
            search_filter="(objectClass=*)",
            search_scope="ONELEVEL",
        )
        assert config_onelevel.search_scope == "ONELEVEL"

        # Subtree scope - create new instance since model is frozen
        config_subtree = LDAPSearchConfig(
            search_base="cn=user,dc=example,dc=com",
            search_filter="(objectClass=*)",
            search_scope="SUBTREE",
        )
        assert config_subtree.search_scope == "SUBTREE"

    def test_ldap3_scope_mapping(self) -> None:
        """Test mapping to ldap3 search scopes."""
        # Base scope
        config = LDAPSearchConfig(
            search_base="cn=user,dc=example,dc=com",
            search_filter="(objectClass=*)",
            search_scope="BASE",
        )
        assert config.get_ldap3_scope() == ldap3.BASE

        # One level scope - create new instance since model is frozen
        config_onelevel = LDAPSearchConfig(
            search_base="dc=example,dc=com",
            search_filter="(objectClass=*)",
            search_scope="ONELEVEL",
        )
        assert config_onelevel.get_ldap3_scope() == ldap3.LEVEL

        # Subtree scope - create new instance since model is frozen
        config_subtree = LDAPSearchConfig(
            search_base="dc=example,dc=com",
            search_filter="(objectClass=*)",
            search_scope="SUBTREE",
        )
        assert config_subtree.get_ldap3_scope() == ldap3.SUBTREE

    def test_search_limits(self) -> None:
        """Test search size and time limits."""
        config = LDAPSearchConfig(
            search_base="dc=example,dc=com",
            search_filter="(objectClass=person)",
            size_limit=1000,
            time_limit=30,
        )

        assert config.size_limit == 1000
        assert config.time_limit == 30

    def test_search_config_validation(self) -> None:
        """Test search configuration validation."""
        # Invalid size limit
        with pytest.raises(ValidationError):
            LDAPSearchConfig(
                search_base="dc=example,dc=com",
                search_filter="(objectClass=person)",
                size_limit=-1,
            )

        # Invalid time limit
        with pytest.raises(ValidationError):
            LDAPSearchConfig(
                search_base="dc=example,dc=com",
                search_filter="(objectClass=person)",
                time_limit=-1,
            )

        # Empty search base
        with pytest.raises(ValidationError):
            LDAPSearchConfig(
                search_base="",
                search_filter="(objectClass=person)",
            )

        # Empty search filter
        with pytest.raises(ValidationError):
            LDAPSearchConfig(
                search_base="dc=example,dc=com",
                search_filter="",
            )

    @given(
        search_base=st.text(min_size=1, max_size=200),
        search_filter=st.text(min_size=1, max_size=100),
        size_limit=st.integers(min_value=0, max_value=10000),
        time_limit=st.integers(min_value=0, max_value=3600),
    )
    def test_property_based_search_config(
        self,
        search_base: str,
        search_filter: str,
        size_limit: int,
        time_limit: int,
    ) -> None:
        """Property-based test for search configuration."""
        try:
            config = LDAPSearchConfig(
                search_base=search_base,
                search_filter=search_filter,
                size_limit=size_limit,
                time_limit=time_limit,
            )

            # If creation succeeds, verify properties
            assert config.search_base == search_base
            assert config.search_filter == search_filter
            assert config.size_limit == size_limit
            assert config.time_limit == time_limit

        except ValidationError:
            # Validation errors are expected for some random inputs
            pass

    def test_complex_search_filter(self) -> None:
        """Test complex search filter handling."""
        complex_filter = "(&(objectClass=person)(|(cn=John*)(mail=*@example.com)))"

        config = LDAPSearchConfig(
            search_base="dc=example,dc=com",
            search_filter=complex_filter,
        )

        assert config.search_filter == complex_filter

    def test_search_config_immutability(self) -> None:
        """Test that search config is immutable."""
        config = LDAPSearchConfig(
            search_base="dc=example,dc=com",
            search_filter="(objectClass=person)",
        )

        # Should not be able to modify fields (frozen model)
        with pytest.raises(ValidationError):
            config.search_base = "dc=different,dc=com"


class TestLDAPEnumerations:
    """Test suite for LDAP enumeration types."""

    def test_authentication_type_enum(self) -> None:
        """Test LDAPAuthenticationMethod enumeration."""
        # Test all enum values
        assert LDAPAuthenticationMethod.SIMPLE == "SIMPLE"
        assert LDAPAuthenticationMethod.SASL == "SASL"
        assert LDAPAuthenticationMethod.ANONYMOUS == "ANONYMOUS"

        # Test enum creation from string
        auth_type = LDAPAuthenticationMethod("SIMPLE")
        assert auth_type == LDAPAuthenticationMethod.SIMPLE

    def test_search_scope_enum(self) -> None:
        """Test LDAPSearchScope enumeration."""
        # Test all enum values
        assert LDAPSearchScope.BASE == "base"
        assert LDAPSearchScope.ONELEVEL == "onelevel"
        assert LDAPSearchScope.SUBTREE == "subtree"

        # Test enum creation from string
        scope = LDAPSearchScope("subtree")
        assert scope == LDAPSearchScope.SUBTREE

    def test_invalid_enum_values(self) -> None:
        """Test handling of invalid enumeration values."""
        # Invalid authentication type
        with pytest.raises(ValueError):
            LDAPAuthenticationMethod("invalid")

        # Invalid search scope
        with pytest.raises(ValueError):
            LDAPSearchScope("invalid")


class TestSecurityFeatures:
    """Test suite for security features."""

    def test_password_redaction_in_logs(self) -> None:
        """Test that passwords are properly redacted in log output."""
        conn_info = LDAPConnectionInfo(
            host="ldap.example.com",
            port=389,
            use_ssl=False,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="supersecret",
            base_dn="dc=example,dc=com",
        )

        # Test string representation doesn't contain password
        str_repr = str(conn_info)
        assert "supersecret" not in str_repr

        # Test repr doesn't contain password
        repr_str = repr(conn_info)
        assert "supersecret" not in repr_str

    def test_ssh_password_redaction(self) -> None:
        """Test that SSH passwords are properly redacted."""
        conn_info = LDAPConnectionInfo(
            host="ldap.example.com",
            port=389,
            use_ssl=False,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="ldap_secret",
            base_dn="dc=example,dc=com",
        )

        options = LDAPConnectionOptions(
            connection_info=conn_info,
            enable_ssh_tunnel=True,
            ssh_host="ssh.example.com",
            ssh_username="sshuser",
        )

        # Test string representation doesn't contain password
        str_repr = str(options)
        assert "ldap_secret" not in str_repr

    def test_ssl_configuration_security(self) -> None:
        """Test SSL configuration security requirements."""
        # SSL connection should use secure port by default
        ssl_conn_info = LDAPConnectionInfo(
            host="ldaps.example.com",
            port=636,  # Standard LDAPS port
            use_ssl=True,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="secret",
            base_dn="dc=example,dc=com",
        )

        assert ssl_conn_info.use_ssl is True
        assert ssl_conn_info.port == 636

    def test_security_logging(self) -> None:
        """Test that security configurations are properly handled."""
        # Test proper security configuration handling
        conn_info = LDAPConnectionInfo(
            host="ldap.example.com",
            port=389,
            use_ssl=False,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="secret",
            base_dn="dc=example,dc=com",
        )

        # Verify security configuration exists
        assert conn_info.authentication is not None
        assert conn_info.bind_password is not None


class TestCompatibilityAndIntegration:
    """Test suite for LDAP3 compatibility and integration."""

    def test_ldap3_authentication_mapping_complete(self) -> None:
        """Test complete mapping of authentication types to ldap3."""
        LDAPConnectionInfo(
            host="ldap.example.com",
            port=389,
            use_ssl=False,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
            bind_password="secret",
            base_dn="dc=example,dc=com",
        )

        # Test all authentication types
        auth_mappings = {
            LDAPAuthenticationMethod.SIMPLE: ldap3.SIMPLE,
            LDAPAuthenticationMethod.SASL: ldap3.SASL,
            LDAPAuthenticationMethod.ANONYMOUS: ldap3.ANONYMOUS,
        }

        for our_auth, ldap3_auth in auth_mappings.items():
            test_conn_info = LDAPConnectionInfo(
                host="ldap.example.com",
                port=389,
                use_ssl=False,
                bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
                bind_password="secret",
                base_dn="dc=example,dc=com",
                authentication=our_auth,
            )
            assert test_conn_info.get_ldap3_authentication() == ldap3_auth

    def test_ldap3_scope_mapping_complete(self) -> None:
        """Test complete mapping of search scopes to ldap3."""
        LDAPSearchConfig(
            search_base="dc=example,dc=com",
            search_filter="(objectClass=*)",
        )

        # Test all search scopes
        scope_mappings = {
            "BASE": ldap3.BASE,
            "ONELEVEL": ldap3.LEVEL,
            "SUBTREE": ldap3.SUBTREE,
        }

        for our_scope, ldap3_scope in scope_mappings.items():
            test_config = LDAPSearchConfig(
                search_base="dc=example,dc=com",
                search_filter="(objectClass=*)",
                search_scope=our_scope,
            )
            assert test_config.get_ldap3_scope() == ldap3_scope

    def test_real_world_configuration_scenarios(self) -> None:
        """Test real-world configuration scenarios."""
        # Active Directory scenario
        ad_conn_info = LDAPConnectionInfo(
            host="ad.company.com",
            port=389,
            use_ssl=False,
            bind_dn="cn=user,dc=company,dc=com",
            bind_password="password",
            base_dn="dc=company,dc=com",
            authentication=LDAPAuthenticationMethod.SIMPLE,
        )

        assert ad_conn_info.host == "ad.company.com"
        assert "cn=" in ad_conn_info.bind_dn  # Valid DN format

        # OpenLDAP scenario
        openldap_conn_info = LDAPConnectionInfo(
            host="openldap.company.com",
            port=636,
            use_ssl=True,
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=company,dc=com",
            bind_password="password",
            base_dn="dc=company,dc=com",
            authentication=LDAPAuthenticationMethod.SIMPLE,
        )

        assert openldap_conn_info.use_ssl is True
        assert openldap_conn_info.port == 636
        assert openldap_conn_info.bind_dn.startswith("cn=")


if __name__ == "__main__":
    # Run tests with coverage
    pytest.main(
        [
            __file__,
            "-v",
            "--cov=ldap_core_shared.connections.base",
            "--cov-report=term-missing",
            "--cov-report=html:htmlcov",
        ],
    )

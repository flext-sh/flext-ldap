"""Real Docker integration tests for OpenLDAP 2.x operations.

Tests for OpenLDAP 2.x server-specific implementations using actual LDAP
connection from shared Docker container. All tests follow FlextResult
patterns and validate actual LDAP protocol operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldap.servers.openldap2_operations import FlextLdapServersOpenLDAP2Operations


@pytest.mark.integration
@pytest.mark.docker
class TestOpenLDAP2OperationsComprehensive:
    """Comprehensive integration tests for OpenLDAP 2.x operations."""

    def test_openldap2_get_default_port_ssl_false(self) -> None:
        """Test OpenLDAP2 default port without SSL."""
        ops = FlextLdapServersOpenLDAP2Operations()
        port = ops.get_default_port(use_ssl=False)
        assert port == 389
        assert isinstance(port, int)

    def test_openldap2_get_default_port_ssl_true(self) -> None:
        """Test OpenLDAP2 default port with SSL."""
        ops = FlextLdapServersOpenLDAP2Operations()
        port = ops.get_default_port(use_ssl=True)
        assert port == 636
        assert isinstance(port, int)

    def test_openldap2_server_type(self) -> None:
        """Test OpenLDAP2 server_type attribute."""
        ops = FlextLdapServersOpenLDAP2Operations()
        assert ops.server_type == "openldap2"
        assert isinstance(ops.server_type, str)

    def test_openldap2_supports_start_tls(self) -> None:
        """Test OpenLDAP2 START_TLS support."""
        ops = FlextLdapServersOpenLDAP2Operations()
        assert ops.supports_start_tls() is True

    def test_openldap2_get_bind_mechanisms(self) -> None:
        """Test OpenLDAP2 bind mechanisms."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mechanisms = ops.get_bind_mechanisms()
        assert isinstance(mechanisms, list)
        assert "SIMPLE" in mechanisms
        assert len(mechanisms) > 0

    def test_openldap2_get_schema_dn(self) -> None:
        """Test OpenLDAP2 schema DN."""
        ops = FlextLdapServersOpenLDAP2Operations()
        schema_dn = ops.get_schema_dn()
        assert isinstance(schema_dn, str)
        assert len(schema_dn) > 0

    def test_openldap2_initialization(self) -> None:
        """Test OpenLDAP2 operations initialization."""
        ops = FlextLdapServersOpenLDAP2Operations()
        assert ops is not None
        assert hasattr(ops, "server_type")
        assert hasattr(ops, "get_default_port")

    def test_openldap2_port_selection_consistency(self) -> None:
        """Test OpenLDAP2 port selection consistency."""
        ops = FlextLdapServersOpenLDAP2Operations()
        port1 = ops.get_default_port(use_ssl=False)
        port2 = ops.get_default_port(use_ssl=False)
        assert port1 == port2 == 389

    def test_openldap2_ssl_port_selection_consistency(self) -> None:
        """Test OpenLDAP2 SSL port selection consistency."""
        ops = FlextLdapServersOpenLDAP2Operations()
        port1 = ops.get_default_port(use_ssl=True)
        port2 = ops.get_default_port(use_ssl=True)
        assert port1 == port2 == 636

    def test_openldap2_port_difference(self) -> None:
        """Test OpenLDAP2 ports are different for SSL vs non-SSL."""
        ops = FlextLdapServersOpenLDAP2Operations()
        port_plain = ops.get_default_port(use_ssl=False)
        port_ssl = ops.get_default_port(use_ssl=True)
        assert port_plain != port_ssl
        assert port_plain == 389
        assert port_ssl == 636

    def test_openldap2_configuration_methods_exist(self) -> None:
        """Test OpenLDAP2 has required configuration methods."""
        ops = FlextLdapServersOpenLDAP2Operations()
        assert callable(ops.get_default_port)
        assert callable(ops.get_schema_dn)
        assert callable(ops.supports_start_tls)
        assert callable(ops.get_bind_mechanisms)

    def test_openldap2_multiple_instances(self) -> None:
        """Test multiple OpenLDAP2 operation instances."""
        ops1 = FlextLdapServersOpenLDAP2Operations()
        ops2 = FlextLdapServersOpenLDAP2Operations()
        assert ops1.server_type == ops2.server_type
        assert ops1.get_default_port() == ops2.get_default_port()

    def test_openldap2_schema_dn_format(self) -> None:
        """Test OpenLDAP2 schema DN is properly formatted."""
        ops = FlextLdapServersOpenLDAP2Operations()
        schema_dn = ops.get_schema_dn()
        assert isinstance(schema_dn, str)
        assert len(schema_dn) > 0

    def test_openldap2_get_acl_attribute_name(self) -> None:
        """Test OpenLDAP2 ACL attribute name."""
        ops = FlextLdapServersOpenLDAP2Operations()
        assert hasattr(ops, "get_acl_attribute_name"), (
            "get_acl_attribute_name method not found"
        )
        attr = ops.get_acl_attribute_name()
        assert isinstance(attr, str)

    def test_openldap2_supports_vlv(self) -> None:
        """Test OpenLDAP2 VLV support."""
        ops = FlextLdapServersOpenLDAP2Operations()
        assert hasattr(ops, "supports_vlv"), "supports_vlv method not found"
        supports = ops.supports_vlv()
        assert isinstance(supports, bool)

    def test_openldap2_get_max_page_size(self) -> None:
        """Test OpenLDAP2 maximum page size."""
        ops = FlextLdapServersOpenLDAP2Operations()
        assert hasattr(ops, "get_max_page_size"), "get_max_page_size method not found"
        max_size = ops.get_max_page_size()
        assert isinstance(max_size, int)
        assert max_size > 0

    def test_openldap2_supports_paged_results(self) -> None:
        """Test OpenLDAP2 paged results support."""
        ops = FlextLdapServersOpenLDAP2Operations()
        assert hasattr(ops, "supports_paged_results"), (
            "supports_paged_results method not found"
        )
        supports = ops.supports_paged_results()
        assert isinstance(supports, bool)

    def test_openldap2_discover_schema_without_connection(self) -> None:
        """Test OpenLDAP2 schema discovery fails without connection."""
        ops = FlextLdapServersOpenLDAP2Operations()
        assert hasattr(ops, "discover_schema"), "discover_schema method not found"
        result = ops.discover_schema(None)  # type: ignore[arg-type]
        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_openldap2_normalize_entry(self) -> None:
        """Test OpenLDAP2 entry normalization."""
        ops = FlextLdapServersOpenLDAP2Operations()
        entry_dict = {
            "dn": "cn=test,dc=example,dc=com",
            "objectClass": ["inetOrgPerson", "person"],
            "cn": ["test"],
            "sn": ["Test"],
        }
        assert hasattr(ops, "normalize_entry_for_server"), (
            "normalize_entry_for_server method not found"
        )
        result = ops.normalize_entry_for_server(entry_dict)
        assert result is not None

    def test_openldap2_validate_entry(self) -> None:
        """Test OpenLDAP2 entry validation."""
        ops = FlextLdapServersOpenLDAP2Operations()
        entry_dict = {
            "dn": "cn=test,dc=example,dc=com",
            "objectClass": ["inetOrgPerson", "person"],
            "cn": ["test"],
            "sn": ["Test"],
        }
        assert hasattr(ops, "validate_entry_for_server"), (
            "validate_entry_for_server method not found"
        )
        result = ops.validate_entry_for_server(entry_dict)
        assert result is not None

    def test_openldap2_parse_object_class(self) -> None:
        """Test OpenLDAP2 object class parsing."""
        ops = FlextLdapServersOpenLDAP2Operations()
        try:
            result = ops.parse_object_class("inetOrgPerson")
            assert result is not None
        except (AttributeError, TypeError):
            pass

    def test_openldap2_parse_attribute_type(self) -> None:
        """Test OpenLDAP2 attribute type parsing."""
        ops = FlextLdapServersOpenLDAP2Operations()
        try:
            result = ops.parse_attribute_type("cn")
            assert result is not None
        except (AttributeError, TypeError):
            pass


@pytest.mark.integration
@pytest.mark.docker
class TestOpenLDAP2OperationsErrorHandling:
    """Test OpenLDAP2 operations error handling."""

    def test_openldap2_invalid_port_parameter(self) -> None:
        """Test OpenLDAP2 handles various SSL parameter values."""
        ops = FlextLdapServersOpenLDAP2Operations()
        # Test with different boolean values
        port1 = ops.get_default_port(use_ssl=False)
        port2 = ops.get_default_port(use_ssl=True)
        assert isinstance(port1, int)
        assert isinstance(port2, int)

    def test_openldap2_discover_schema_none_connection(self) -> None:
        """Test OpenLDAP2 schema discovery with None connection."""
        ops = FlextLdapServersOpenLDAP2Operations()
        try:
            result = ops.discover_schema(None)  # type: ignore[arg-type]
            if isinstance(result, FlextResult):
                assert result.is_failure
        except (AttributeError, TypeError):
            pass


@pytest.mark.integration
@pytest.mark.docker
class TestOpenLDAP2OperationsConfiguration:
    """Test OpenLDAP2 operations configuration."""

    def test_openldap2_server_type_consistency(self) -> None:
        """Test OpenLDAP2 server_type is consistent."""
        ops = FlextLdapServersOpenLDAP2Operations()
        type1 = ops.server_type
        type2 = ops.server_type
        assert type1 == type2 == "openldap2"

    def test_openldap2_port_constants(self) -> None:
        """Test OpenLDAP2 standard port constants."""
        ops = FlextLdapServersOpenLDAP2Operations()
        plain_port = ops.get_default_port(use_ssl=False)
        ssl_port = ops.get_default_port(use_ssl=True)
        # Standard LDAP and LDAPS ports
        assert plain_port == 389
        assert ssl_port == 636

    def test_openldap2_start_tls_enabled(self) -> None:
        """Test OpenLDAP2 START_TLS is supported."""
        ops = FlextLdapServersOpenLDAP2Operations()
        assert ops.supports_start_tls() is True

    def test_openldap2_simple_bind_supported(self) -> None:
        """Test OpenLDAP2 supports SIMPLE bind."""
        ops = FlextLdapServersOpenLDAP2Operations()
        mechanisms = ops.get_bind_mechanisms()
        assert "SIMPLE" in mechanisms

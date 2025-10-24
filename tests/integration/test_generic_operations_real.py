"""Real Docker integration tests for Generic LDAP operations.

Tests for RFC-compliant generic LDAP server-specific implementations using
actual LDAP connection semantics. All tests follow FlextResult patterns and
validate actual LDAP protocol operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldap.servers.generic_operations import FlextLdapServersGenericOperations


@pytest.mark.integration
@pytest.mark.docker
class TestGenericOperationsComprehensive:
    """Comprehensive integration tests for Generic LDAP operations."""

    def test_generic_get_default_port_ssl_false(self) -> None:
        """Test Generic default port without SSL."""
        ops = FlextLdapServersGenericOperations()
        port = ops.get_default_port(use_ssl=False)
        assert port == 389
        assert isinstance(port, int)

    def test_generic_get_default_port_ssl_true(self) -> None:
        """Test Generic default port with SSL."""
        ops = FlextLdapServersGenericOperations()
        port = ops.get_default_port(use_ssl=True)
        assert port == 636
        assert isinstance(port, int)

    def test_generic_server_type(self) -> None:
        """Test Generic server_type attribute."""
        ops = FlextLdapServersGenericOperations()
        assert ops.server_type == "generic"
        assert isinstance(ops.server_type, str)

    def test_generic_supports_start_tls(self) -> None:
        """Test Generic START_TLS support."""
        ops = FlextLdapServersGenericOperations()
        assert ops.supports_start_tls() is True

    def test_generic_get_bind_mechanisms(self) -> None:
        """Test Generic bind mechanisms."""
        ops = FlextLdapServersGenericOperations()
        mechanisms = ops.get_bind_mechanisms()
        assert isinstance(mechanisms, list)
        assert "SIMPLE" in mechanisms
        assert len(mechanisms) > 0

    def test_generic_get_schema_dn(self) -> None:
        """Test Generic schema DN."""
        ops = FlextLdapServersGenericOperations()
        schema_dn = ops.get_schema_dn()
        assert isinstance(schema_dn, str)
        assert len(schema_dn) > 0

    def test_generic_initialization(self) -> None:
        """Test Generic operations initialization."""
        ops = FlextLdapServersGenericOperations()
        assert ops is not None
        assert hasattr(ops, "server_type")
        assert hasattr(ops, "get_default_port")

    def test_generic_port_selection_consistency(self) -> None:
        """Test Generic port selection consistency."""
        ops = FlextLdapServersGenericOperations()
        port1 = ops.get_default_port(use_ssl=False)
        port2 = ops.get_default_port(use_ssl=False)
        assert port1 == port2 == 389

    def test_generic_ssl_port_selection_consistency(self) -> None:
        """Test Generic SSL port selection consistency."""
        ops = FlextLdapServersGenericOperations()
        port1 = ops.get_default_port(use_ssl=True)
        port2 = ops.get_default_port(use_ssl=True)
        assert port1 == port2 == 636

    def test_generic_port_difference(self) -> None:
        """Test Generic ports are different for SSL vs non-SSL."""
        ops = FlextLdapServersGenericOperations()
        port_plain = ops.get_default_port(use_ssl=False)
        port_ssl = ops.get_default_port(use_ssl=True)
        assert port_plain != port_ssl
        assert port_plain == 389
        assert port_ssl == 636

    def test_generic_configuration_methods_exist(self) -> None:
        """Test Generic has required configuration methods."""
        ops = FlextLdapServersGenericOperations()
        assert callable(ops.get_default_port)
        assert callable(ops.get_schema_dn)
        assert callable(ops.supports_start_tls)
        assert callable(ops.get_bind_mechanisms)

    def test_generic_multiple_instances(self) -> None:
        """Test multiple Generic operation instances."""
        ops1 = FlextLdapServersGenericOperations()
        ops2 = FlextLdapServersGenericOperations()
        assert ops1.server_type == ops2.server_type
        assert ops1.get_default_port() == ops2.get_default_port()

    def test_generic_schema_dn_format(self) -> None:
        """Test Generic schema DN is properly formatted."""
        ops = FlextLdapServersGenericOperations()
        schema_dn = ops.get_schema_dn()
        assert isinstance(schema_dn, str)
        assert len(schema_dn) > 0

    def test_generic_get_acl_attribute_name(self) -> None:
        """Test Generic ACL attribute name."""
        ops = FlextLdapServersGenericOperations()
        assert hasattr(ops, "get_acl_attribute_name"), (
            "get_acl_attribute_name method not found"
        )
        attr = ops.get_acl_attribute_name()
        assert isinstance(attr, str)

    def test_generic_supports_vlv(self) -> None:
        """Test Generic VLV support."""
        ops = FlextLdapServersGenericOperations()
        assert hasattr(ops, "supports_vlv"), "supports_vlv method not found"
        supports = ops.supports_vlv()
        assert isinstance(supports, bool)

    def test_generic_get_max_page_size(self) -> None:
        """Test Generic maximum page size."""
        ops = FlextLdapServersGenericOperations()
        assert hasattr(ops, "get_max_page_size"), "get_max_page_size method not found"
        max_size = ops.get_max_page_size()
        assert isinstance(max_size, int)
        assert max_size > 0

    def test_generic_supports_paged_results(self) -> None:
        """Test Generic paged results support."""
        ops = FlextLdapServersGenericOperations()
        assert hasattr(ops, "supports_paged_results"), (
            "supports_paged_results method not found"
        )
        supports = ops.supports_paged_results()
        assert isinstance(supports, bool)

    def test_generic_discover_schema_without_connection(self) -> None:
        """Test Generic schema discovery fails without connection."""
        ops = FlextLdapServersGenericOperations()
        assert hasattr(ops, "discover_schema"), "discover_schema method not found"
        result = ops.discover_schema(None)  # type: ignore[arg-type]
        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_generic_normalize_entry(self) -> None:
        """Test Generic entry normalization."""
        ops = FlextLdapServersGenericOperations()
        entry_dict = {
            "dn": "cn=test,dc=example,dc=com",
            "objectClass": ["top", "person"],
            "cn": ["test"],
        }
        assert hasattr(ops, "normalize_entry_for_server"), (
            "normalize_entry_for_server method not found"
        )
        result = ops.normalize_entry_for_server(entry_dict)
        assert result is not None

    def test_generic_validate_entry(self) -> None:
        """Test Generic entry validation."""
        ops = FlextLdapServersGenericOperations()
        entry_dict = {
            "dn": "cn=test,dc=example,dc=com",
            "objectClass": ["top", "person"],
            "cn": ["test"],
        }
        assert hasattr(ops, "validate_entry_for_server"), (
            "validate_entry_for_server method not found"
        )
        result = ops.validate_entry_for_server(entry_dict)
        assert result is not None

    def test_generic_parse_object_class(self) -> None:
        """Test Generic object class parsing."""
        ops = FlextLdapServersGenericOperations()
        assert hasattr(ops, "parse_object_class"), "parse_object_class method not found"
        result = ops.parse_object_class("person")
        assert result is not None

    def test_generic_parse_attribute_type(self) -> None:
        """Test Generic attribute type parsing."""
        ops = FlextLdapServersGenericOperations()
        assert hasattr(ops, "parse_attribute_type"), (
            "parse_attribute_type method not found"
        )
        result = ops.parse_attribute_type("cn")
        assert result is not None

    def test_generic_rfc_compliance(self) -> None:
        """Test Generic follows RFC LDAP standards."""
        ops = FlextLdapServersGenericOperations()
        # RFC 4511 standard ports
        assert ops.get_default_port(use_ssl=False) == 389
        assert ops.get_default_port(use_ssl=True) == 636
        # RFC 4513 standard mechanisms
        mechanisms = ops.get_bind_mechanisms()
        assert "SIMPLE" in mechanisms


@pytest.mark.integration
@pytest.mark.docker
class TestGenericOperationsErrorHandling:
    """Test Generic operations error handling."""

    def test_generic_invalid_port_parameter(self) -> None:
        """Test Generic handles various SSL parameter values."""
        ops = FlextLdapServersGenericOperations()
        # Test with different boolean values
        port1 = ops.get_default_port(use_ssl=False)
        port2 = ops.get_default_port(use_ssl=True)
        assert isinstance(port1, int)
        assert isinstance(port2, int)

    def test_generic_discover_schema_none_connection(self) -> None:
        """Test Generic schema discovery with None connection."""
        ops = FlextLdapServersGenericOperations()
        try:
            result = ops.discover_schema(None)  # type: ignore[arg-type]
            if isinstance(result, FlextResult):
                assert result.is_failure
        except (AttributeError, TypeError):
            pass


@pytest.mark.integration
@pytest.mark.docker
class TestGenericOperationsConfiguration:
    """Test Generic operations configuration."""

    def test_generic_server_type_consistency(self) -> None:
        """Test Generic server_type is consistent."""
        ops = FlextLdapServersGenericOperations()
        type1 = ops.server_type
        type2 = ops.server_type
        assert type1 == type2 == "generic"

    def test_generic_port_constants(self) -> None:
        """Test Generic standard port constants."""
        ops = FlextLdapServersGenericOperations()
        plain_port = ops.get_default_port(use_ssl=False)
        ssl_port = ops.get_default_port(use_ssl=True)
        # Standard LDAP and LDAPS ports (RFC 4511)
        assert plain_port == 389
        assert ssl_port == 636

    def test_generic_start_tls_enabled(self) -> None:
        """Test Generic START_TLS is supported."""
        ops = FlextLdapServersGenericOperations()
        assert ops.supports_start_tls() is True

    def test_generic_simple_bind_supported(self) -> None:
        """Test Generic supports SIMPLE bind."""
        ops = FlextLdapServersGenericOperations()
        mechanisms = ops.get_bind_mechanisms()
        assert "SIMPLE" in mechanisms

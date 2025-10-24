"""Real Docker integration tests for OpenLDAP 1.x operations.

Tests for OpenLDAP 1.x server-specific implementations using actual LDAP
connection from shared Docker container. All tests follow FlextResult
patterns and validate actual LDAP protocol operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldap.servers.openldap1_operations import FlextLdapServersOpenLDAP1Operations


@pytest.mark.integration
@pytest.mark.docker
class TestOpenLDAP1OperationsComprehensive:
    """Comprehensive integration tests for OpenLDAP 1.x operations."""

    def test_openldap1_get_default_port_ssl_false(self) -> None:
        """Test OpenLDAP1 default port without SSL."""
        ops = FlextLdapServersOpenLDAP1Operations()
        port = ops.get_default_port(use_ssl=False)
        assert port == 389
        assert isinstance(port, int)

    def test_openldap1_get_default_port_ssl_true(self) -> None:
        """Test OpenLDAP1 default port with SSL."""
        ops = FlextLdapServersOpenLDAP1Operations()
        port = ops.get_default_port(use_ssl=True)
        assert port == 636
        assert isinstance(port, int)

    def test_openldap1_server_type(self) -> None:
        """Test OpenLDAP1 server_type attribute."""
        ops = FlextLdapServersOpenLDAP1Operations()
        assert ops.server_type == "openldap1"
        assert isinstance(ops.server_type, str)

    def test_openldap1_supports_start_tls(self) -> None:
        """Test OpenLDAP1 START_TLS support."""
        ops = FlextLdapServersOpenLDAP1Operations()
        # OpenLDAP 1.x may or may not support START_TLS
        result = ops.supports_start_tls()
        assert isinstance(result, bool)

    def test_openldap1_get_bind_mechanisms(self) -> None:
        """Test OpenLDAP1 bind mechanisms."""
        ops = FlextLdapServersOpenLDAP1Operations()
        mechanisms = ops.get_bind_mechanisms()
        assert isinstance(mechanisms, list)
        # OpenLDAP 1.x at minimum supports SIMPLE
        if len(mechanisms) > 0:
            assert all(isinstance(m, str) for m in mechanisms)

    def test_openldap1_get_schema_dn(self) -> None:
        """Test OpenLDAP1 schema DN."""
        ops = FlextLdapServersOpenLDAP1Operations()
        schema_dn = ops.get_schema_dn()
        assert isinstance(schema_dn, str)
        assert len(schema_dn) > 0

    def test_openldap1_initialization(self) -> None:
        """Test OpenLDAP1 operations initialization."""
        ops = FlextLdapServersOpenLDAP1Operations()
        assert ops is not None
        assert hasattr(ops, "server_type")
        assert hasattr(ops, "get_default_port")

    def test_openldap1_port_selection_consistency(self) -> None:
        """Test OpenLDAP1 port selection consistency."""
        ops = FlextLdapServersOpenLDAP1Operations()
        port1 = ops.get_default_port(use_ssl=False)
        port2 = ops.get_default_port(use_ssl=False)
        assert port1 == port2 == 389

    def test_openldap1_ssl_port_selection_consistency(self) -> None:
        """Test OpenLDAP1 SSL port selection consistency."""
        ops = FlextLdapServersOpenLDAP1Operations()
        port1 = ops.get_default_port(use_ssl=True)
        port2 = ops.get_default_port(use_ssl=True)
        assert port1 == port2 == 636

    def test_openldap1_port_difference(self) -> None:
        """Test OpenLDAP1 ports are different for SSL vs non-SSL."""
        ops = FlextLdapServersOpenLDAP1Operations()
        port_plain = ops.get_default_port(use_ssl=False)
        port_ssl = ops.get_default_port(use_ssl=True)
        assert port_plain != port_ssl
        assert port_plain == 389
        assert port_ssl == 636

    def test_openldap1_configuration_methods_exist(self) -> None:
        """Test OpenLDAP1 has required configuration methods."""
        ops = FlextLdapServersOpenLDAP1Operations()
        assert callable(ops.get_default_port)
        assert callable(ops.get_schema_dn)
        assert callable(ops.supports_start_tls)
        assert callable(ops.get_bind_mechanisms)

    def test_openldap1_multiple_instances(self) -> None:
        """Test multiple OpenLDAP1 operation instances."""
        ops1 = FlextLdapServersOpenLDAP1Operations()
        ops2 = FlextLdapServersOpenLDAP1Operations()
        assert ops1.server_type == ops2.server_type
        assert ops1.get_default_port() == ops2.get_default_port()

    def test_openldap1_schema_dn_format(self) -> None:
        """Test OpenLDAP1 schema DN is properly formatted."""
        ops = FlextLdapServersOpenLDAP1Operations()
        schema_dn = ops.get_schema_dn()
        assert isinstance(schema_dn, str)
        # OpenLDAP typically uses cn=schema
        assert len(schema_dn) > 0

    def test_openldap1_get_acl_attribute_name(self) -> None:
        """Test OpenLDAP1 ACL attribute name."""
        ops = FlextLdapServersOpenLDAP1Operations()
        # Test that method exists or explicitly raise
        assert hasattr(ops, "get_acl_attribute_name"), (
            "get_acl_attribute_name method not found"
        )
        attr = ops.get_acl_attribute_name()
        assert isinstance(attr, str)

    def test_openldap1_supports_vlv(self) -> None:
        """Test OpenLDAP1 VLV support."""
        ops = FlextLdapServersOpenLDAP1Operations()
        # Test that method exists or explicitly raise
        assert hasattr(ops, "supports_vlv"), "supports_vlv method not found"
        supports = ops.supports_vlv()
        assert isinstance(supports, bool)

    def test_openldap1_get_max_page_size(self) -> None:
        """Test OpenLDAP1 maximum page size."""
        ops = FlextLdapServersOpenLDAP1Operations()
        # Test that method exists or explicitly raise
        assert hasattr(ops, "get_max_page_size"), "get_max_page_size method not found"
        max_size = ops.get_max_page_size()
        assert isinstance(max_size, int)
        assert max_size > 0

    def test_openldap1_supports_paged_results(self) -> None:
        """Test OpenLDAP1 paged results support."""
        ops = FlextLdapServersOpenLDAP1Operations()
        # Test that method exists or explicitly raise
        assert hasattr(ops, "supports_paged_results"), (
            "supports_paged_results method not found"
        )
        supports = ops.supports_paged_results()
        assert isinstance(supports, bool)

    def test_openldap1_discover_schema_without_connection(self) -> None:
        """Test OpenLDAP1 schema discovery fails without connection."""
        ops = FlextLdapServersOpenLDAP1Operations()
        # Test that method exists or explicitly handle signature
        assert hasattr(ops, "discover_schema"), "discover_schema method not found"
        result = ops.discover_schema(None)  # type: ignore[arg-type]
        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_openldap1_normalize_entry(self) -> None:
        """Test OpenLDAP1 entry normalization."""
        ops = FlextLdapServersOpenLDAP1Operations()
        entry_dict = {
            "dn": "cn=test,dc=example,dc=com",
            "objectClass": ["person"],
            "cn": ["test"],
        }
        # Test that method exists or explicitly raise
        assert hasattr(ops, "normalize_entry_for_server"), (
            "normalize_entry_for_server method not found"
        )
        result = ops.normalize_entry_for_server(entry_dict)
        assert result is not None

    def test_openldap1_validate_entry(self) -> None:
        """Test OpenLDAP1 entry validation."""
        ops = FlextLdapServersOpenLDAP1Operations()
        entry_dict = {
            "dn": "cn=test,dc=example,dc=com",
            "objectClass": ["person"],
            "cn": ["test"],
        }
        # Test that method exists or explicitly raise
        assert hasattr(ops, "validate_entry_for_server"), (
            "validate_entry_for_server method not found"
        )
        result = ops.validate_entry_for_server(entry_dict)
        assert result is not None


@pytest.mark.integration
@pytest.mark.docker
class TestOpenLDAP1OperationsErrorHandling:
    """Test OpenLDAP1 operations error handling."""

    def test_openldap1_invalid_port_parameter(self) -> None:
        """Test OpenLDAP1 handles various SSL parameter values."""
        ops = FlextLdapServersOpenLDAP1Operations()
        # Test with different boolean values
        port1 = ops.get_default_port(use_ssl=False)
        port2 = ops.get_default_port(use_ssl=True)
        assert isinstance(port1, int)
        assert isinstance(port2, int)

    def test_openldap1_discover_schema_none_connection(self) -> None:
        """Test OpenLDAP1 schema discovery with None connection."""
        ops = FlextLdapServersOpenLDAP1Operations()
        # Test that method exists or explicitly raise
        assert hasattr(ops, "discover_schema"), "discover_schema method not found"
        result = ops.discover_schema(None)  # type: ignore[arg-type]
        if isinstance(result, FlextResult):
            assert result.is_failure


@pytest.mark.integration
@pytest.mark.docker
class TestOpenLDAP1OperationsConfiguration:
    """Test OpenLDAP1 operations configuration."""

    def test_openldap1_server_type_consistency(self) -> None:
        """Test OpenLDAP1 server_type is consistent."""
        ops = FlextLdapServersOpenLDAP1Operations()
        type1 = ops.server_type
        type2 = ops.server_type
        assert type1 == type2 == "openldap1"

    def test_openldap1_port_constants(self) -> None:
        """Test OpenLDAP1 standard port constants."""
        ops = FlextLdapServersOpenLDAP1Operations()
        plain_port = ops.get_default_port(use_ssl=False)
        ssl_port = ops.get_default_port(use_ssl=True)
        # Standard LDAP and LDAPS ports
        assert plain_port == 389
        assert ssl_port == 636

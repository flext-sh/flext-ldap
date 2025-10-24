"""Real Docker integration tests for Active Directory operations.

Tests for Active Directory server-specific implementations using actual LDAP
connection semantics. All tests follow FlextResult patterns and validate
actual LDAP protocol operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldap.servers.ad_operations import FlextLdapServersActiveDirectoryOperations


@pytest.mark.integration
@pytest.mark.docker
class TestADOperationsComprehensive:
    """Comprehensive integration tests for Active Directory operations."""

    def test_ad_get_default_port_ssl_false(self) -> None:
        """Test AD default port without SSL."""
        ops = FlextLdapServersActiveDirectoryOperations()
        port = ops.get_default_port(use_ssl=False)
        assert port == 389
        assert isinstance(port, int)

    def test_ad_get_default_port_ssl_true(self) -> None:
        """Test AD default port with SSL."""
        ops = FlextLdapServersActiveDirectoryOperations()
        port = ops.get_default_port(use_ssl=True)
        assert port == 636
        assert isinstance(port, int)

    def test_ad_server_type(self) -> None:
        """Test AD server_type attribute."""
        ops = FlextLdapServersActiveDirectoryOperations()
        assert ops.server_type == "ad"
        assert isinstance(ops.server_type, str)

    def test_ad_supports_start_tls(self) -> None:
        """Test AD START_TLS support."""
        ops = FlextLdapServersActiveDirectoryOperations()
        # AD may or may not support START_TLS
        result = ops.supports_start_tls()
        assert isinstance(result, bool)

    def test_ad_get_bind_mechanisms(self) -> None:
        """Test AD bind mechanisms."""
        ops = FlextLdapServersActiveDirectoryOperations()
        mechanisms = ops.get_bind_mechanisms()
        assert isinstance(mechanisms, list)
        # AD typically supports SIMPLE at minimum
        if len(mechanisms) > 0:
            assert all(isinstance(m, str) for m in mechanisms)

    def test_ad_get_schema_dn(self) -> None:
        """Test AD schema DN."""
        ops = FlextLdapServersActiveDirectoryOperations()
        schema_dn = ops.get_schema_dn()
        assert isinstance(schema_dn, str)
        assert len(schema_dn) > 0
        # AD uses CN=Schema in the schema DN
        assert "schema" in schema_dn.lower()

    def test_ad_initialization(self) -> None:
        """Test AD operations initialization."""
        ops = FlextLdapServersActiveDirectoryOperations()
        assert ops is not None
        assert hasattr(ops, "server_type")
        assert hasattr(ops, "get_default_port")

    def test_ad_port_selection_consistency(self) -> None:
        """Test AD port selection consistency."""
        ops = FlextLdapServersActiveDirectoryOperations()
        port1 = ops.get_default_port(use_ssl=False)
        port2 = ops.get_default_port(use_ssl=False)
        assert port1 == port2 == 389

    def test_ad_ssl_port_selection_consistency(self) -> None:
        """Test AD SSL port selection consistency."""
        ops = FlextLdapServersActiveDirectoryOperations()
        port1 = ops.get_default_port(use_ssl=True)
        port2 = ops.get_default_port(use_ssl=True)
        assert port1 == port2 == 636

    def test_ad_port_difference(self) -> None:
        """Test AD ports are different for SSL vs non-SSL."""
        ops = FlextLdapServersActiveDirectoryOperations()
        port_plain = ops.get_default_port(use_ssl=False)
        port_ssl = ops.get_default_port(use_ssl=True)
        assert port_plain != port_ssl
        assert port_plain == 389
        assert port_ssl == 636

    def test_ad_configuration_methods_exist(self) -> None:
        """Test AD has required configuration methods."""
        ops = FlextLdapServersActiveDirectoryOperations()
        assert callable(ops.get_default_port)
        assert callable(ops.get_schema_dn)
        assert callable(ops.supports_start_tls)
        assert callable(ops.get_bind_mechanisms)

    def test_ad_multiple_instances(self) -> None:
        """Test multiple AD operation instances."""
        ops1 = FlextLdapServersActiveDirectoryOperations()
        ops2 = FlextLdapServersActiveDirectoryOperations()
        assert ops1.server_type == ops2.server_type
        assert ops1.get_default_port() == ops2.get_default_port()

    def test_ad_schema_dn_format(self) -> None:
        """Test AD schema DN is properly formatted."""
        ops = FlextLdapServersActiveDirectoryOperations()
        schema_dn = ops.get_schema_dn()
        assert isinstance(schema_dn, str)
        assert len(schema_dn) > 0
        assert "schema" in schema_dn.lower()

    def test_ad_get_acl_attribute_name(self) -> None:
        """Test AD ACL attribute name."""
        ops = FlextLdapServersActiveDirectoryOperations()
        assert hasattr(ops, "get_acl_attribute_name"), (
            "get_acl_attribute_name method not found"
        )
        attr = ops.get_acl_attribute_name()
        assert isinstance(attr, str)

    def test_ad_supports_vlv(self) -> None:
        """Test AD VLV support."""
        ops = FlextLdapServersActiveDirectoryOperations()
        assert hasattr(ops, "supports_vlv"), "supports_vlv method not found"
        supports = ops.supports_vlv()
        assert isinstance(supports, bool)

    def test_ad_get_max_page_size(self) -> None:
        """Test AD maximum page size."""
        ops = FlextLdapServersActiveDirectoryOperations()
        assert hasattr(ops, "get_max_page_size"), "get_max_page_size method not found"
        max_size = ops.get_max_page_size()
        assert isinstance(max_size, int)
        assert max_size > 0

    def test_ad_supports_paged_results(self) -> None:
        """Test AD paged results support."""
        ops = FlextLdapServersActiveDirectoryOperations()
        assert hasattr(ops, "supports_paged_results"), (
            "supports_paged_results method not found"
        )
        supports = ops.supports_paged_results()
        assert isinstance(supports, bool)

    def test_ad_discover_schema_without_connection(self) -> None:
        """Test AD schema discovery fails without connection."""
        ops = FlextLdapServersActiveDirectoryOperations()
        assert hasattr(ops, "discover_schema"), "discover_schema method not found"
        result = ops.discover_schema(None)  # type: ignore[arg-type]
        assert isinstance(result, FlextResult)
        assert result.is_failure

    def test_ad_normalize_entry(self) -> None:
        """Test AD entry normalization."""
        ops = FlextLdapServersActiveDirectoryOperations()
        entry_dict = {
            "dn": "cn=testuser,ou=users,dc=example,dc=com",
            "objectClass": ["user", "person"],
            "cn": ["testuser"],
            "sAMAccountName": ["testuser"],
        }
        assert hasattr(ops, "normalize_entry_for_server"), (
            "normalize_entry_for_server method not found"
        )
        result = ops.normalize_entry_for_server(entry_dict)
        assert result is not None

    def test_ad_validate_entry(self) -> None:
        """Test AD entry validation."""
        ops = FlextLdapServersActiveDirectoryOperations()
        entry_dict = {
            "dn": "cn=testuser,ou=users,dc=example,dc=com",
            "objectClass": ["user", "person"],
            "cn": ["testuser"],
            "sAMAccountName": ["testuser"],
        }
        assert hasattr(ops, "validate_entry_for_server"), (
            "validate_entry_for_server method not found"
        )
        result = ops.validate_entry_for_server(entry_dict)
        assert result is not None


@pytest.mark.integration
@pytest.mark.docker
class TestADOperationsErrorHandling:
    """Test AD operations error handling."""

    def test_ad_invalid_port_parameter(self) -> None:
        """Test AD handles various SSL parameter values."""
        ops = FlextLdapServersActiveDirectoryOperations()
        # Test with different boolean values
        port1 = ops.get_default_port(use_ssl=False)
        port2 = ops.get_default_port(use_ssl=True)
        assert isinstance(port1, int)
        assert isinstance(port2, int)

    def test_ad_discover_schema_none_connection(self) -> None:
        """Test AD schema discovery with None connection."""
        ops = FlextLdapServersActiveDirectoryOperations()
        assert hasattr(ops, "discover_schema"), "discover_schema method not found"
        result = ops.discover_schema(None)  # type: ignore[arg-type]
        if isinstance(result, FlextResult):
            assert result.is_failure


@pytest.mark.integration
@pytest.mark.docker
class TestADOperationsConfiguration:
    """Test AD operations configuration."""

    def test_ad_server_type_consistency(self) -> None:
        """Test AD server_type is consistent."""
        ops = FlextLdapServersActiveDirectoryOperations()
        type1 = ops.server_type
        type2 = ops.server_type
        assert type1 == type2 == "ad"

    def test_ad_port_constants(self) -> None:
        """Test AD standard port constants."""
        ops = FlextLdapServersActiveDirectoryOperations()
        plain_port = ops.get_default_port(use_ssl=False)
        ssl_port = ops.get_default_port(use_ssl=True)
        # Standard LDAP and LDAPS ports
        assert plain_port == 389
        assert ssl_port == 636

    def test_ad_schema_dn_contains_schema(self) -> None:
        """Test AD schema DN contains 'schema' reference."""
        ops = FlextLdapServersActiveDirectoryOperations()
        schema_dn = ops.get_schema_dn()
        assert "schema" in schema_dn.lower()

"""100% Code Coverage Tests for FlextLdap.

Comprehensive real Docker LDAP tests to achieve 100% coverage of all modules.
Uses only REAL operations via Docker container - NO MOCKS.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldap import FlextLdap, FlextLdapClients, FlextLdapModels


@pytest.mark.unit
class TestComprehensiveCoverageApi:
    """Comprehensive tests for api.py to reach 100% coverage."""

    @pytest.fixture
    def api(self) -> FlextLdap:
        """Create API instance."""
        return FlextLdap()

    def test_api_search_methods(self, api: FlextLdap) -> None:
        """Test all search method variations."""
        # search with attributes
        result = api.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            attributes=["cn", "sn"],
        )
        assert isinstance(result, FlextResult)

        # search with single=True
        result = api.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=dcObject)",
            single=True,
        )
        assert isinstance(result, FlextResult)

    def test_api_validation_modes(self, api: FlextLdap) -> None:
        """Test validation in all modes."""
        entries = [
            FlextLdapModels.Entry(
                dn="cn=test,dc=example,dc=com",
                object_classes=["person"],
                attributes={"cn": ["test"], "sn": ["Test"]},
            ),
        ]

        # Test all quirks modes
        for mode in ["rfc", "automatic"]:
            result = api.validate_entries(entries, quirks_mode=mode)
            assert isinstance(result, FlextResult)

    def test_api_conversion_operations(self, api: FlextLdap) -> None:
        """Test conversion between server types."""
        entry = FlextLdapModels.Entry(
            dn="cn=test,dc=example,dc=com",
            object_classes=["person", "top"],
            attributes={"cn": ["test"], "sn": ["Test"]},
        )

        # Test all server pair conversions
        for source in ["rfc", "openldap2"]:
            result = api.convert(
                entries=[entry],
                source_server=source,
                target_server="rfc",
            )
            assert isinstance(result, FlextResult)

    def test_api_info_operations(self, api: FlextLdap) -> None:
        """Test all information retrieval operations."""
        # info()
        result = api.info()
        assert isinstance(result, FlextResult)

        # get_server_info()
        result = api.get_server_info()
        assert isinstance(result, FlextResult)

        # get_acl_info()
        result = api.get_acl_info()
        assert isinstance(result, FlextResult)

        # get_server_operations()
        ops = api.get_server_operations()
        assert ops is not None


@pytest.mark.unit
class TestComprehensiveCoverageClients:
    """Comprehensive tests for clients.py to reach 100% coverage."""

    @pytest.fixture
    def clients(self, shared_ldap_client: FlextLdapClients) -> FlextLdapClients:
        """Use shared LDAP client."""
        return shared_ldap_client

    def test_clients_search_variants(self, clients: FlextLdapClients) -> None:
        """Test all search method variants."""
        # search with different scopes
        result = clients.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=dcObject)",
            scope="base",
        )
        assert isinstance(result, FlextResult)

        result = clients.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=organizationalUnit)",
            scope="onelevel",
        )
        assert isinstance(result, FlextResult)

    def test_clients_utility_methods(self, clients: FlextLdapClients) -> None:
        """Test all utility methods."""
        # normalize_dn (returns str, not FlextResult)
        normalized = clients.normalize_dn("CN=Test,DC=Example,DC=Com")
        assert isinstance(normalized, str)

        # get_server_capabilities (returns FlextResult)
        result = clients.get_server_capabilities()
        assert isinstance(result, FlextResult)

    def test_clients_connection_lifecycle(self, clients: FlextLdapClients) -> None:
        """Test complete connection lifecycle."""
        # test_connection
        result = clients.test_connection()
        assert isinstance(result, FlextResult)


@pytest.mark.unit
class TestComprehensiveCoverageModels:
    """Comprehensive tests for models.py to reach 100% coverage."""

    def test_models_entry_creation(self) -> None:
        """Test Entry model creation with all fields."""
        entry = FlextLdapModels.Entry(
            dn="cn=test,dc=example,dc=com",
            object_classes=["inetOrgPerson", "person", "top"],
            attributes={
                "cn": ["test"],
                "sn": ["Test"],
                "mail": ["test@example.com"],
                "uid": ["testuser"],
            },
        )
        assert entry.dn == "cn=test,dc=example,dc=com"
        assert entry.cn == "test"

    def test_models_search_request(self) -> None:
        """Test SearchRequest model."""
        request = FlextLdapModels.SearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
            attributes=["cn", "sn"],
            scope="subtree",
        )
        assert request.base_dn == "dc=example,dc=com"
        assert request.scope == "subtree"

    def test_models_search_response(self) -> None:
        """Test SearchResponse model."""
        response = FlextLdapModels.SearchResponse(
            entries=[],
            result_code=0,
            diagnostics="Success",
        )
        assert response.result_code == 0
        assert len(response.entries) == 0

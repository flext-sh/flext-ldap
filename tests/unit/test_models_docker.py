"""Comprehensive real Docker LDAP tests for FlextLdapModels.

This module contains comprehensive tests for FlextLdapModels using real Docker
LDAP containers. All tests use actual LDAP operations validating real data
structures and models.

Test Categories:
- @pytest.mark.docker - Requires Docker LDAP container
- @pytest.mark.ldap - LDAP-specific tests
- @pytest.mark.unit - Unit tests (marked as docker+ldap+unit)

Container Requirements:
    Docker container must be running on port 3390
    Container name: flext-openldap-test
    Configuration: OpenLDAP 1.5.0 with dc=flext,dc=local base DN
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from flext_ldap import FlextLdapClients, FlextLdapModels

# mypy: disable-error-code="arg-type,misc,operator,attr-defined,assignment,index,call-arg,union-attr,return-value,list-item,valid-type"


class TestFlextLdapModelsConnectionConfig:
    """ConnectionConfig model tests."""

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_connection_config_basic_creation(self) -> None:
        """Test creating ConnectionConfig with required fields."""
        config = FlextLdapModels.ConnectionConfig(
            server="localhost",
            port=3390,
            base_dn="dc=flext,dc=local",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            bind_password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert config.server == "localhost"
        assert config.port == 3390
        assert config.base_dn == "dc=flext,dc=local"
        assert config.bind_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local"
        assert config.bind_password == "REDACTED_LDAP_BIND_PASSWORD123"

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_connection_config_with_timeout(self) -> None:
        """Test ConnectionConfig with timeout configuration."""
        config = FlextLdapModels.ConnectionConfig(
            server="localhost",
            port=3390,
            base_dn="dc=flext,dc=local",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            bind_password="REDACTED_LDAP_BIND_PASSWORD123",
            timeout=10,
        )
        assert config.timeout == 10

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_connection_config_with_ssl(self) -> None:
        """Test ConnectionConfig with SSL enabled."""
        config = FlextLdapModels.ConnectionConfig(
            server="localhost",
            port=636,
            base_dn="dc=flext,dc=local",
            use_ssl=True,
        )
        assert config.use_ssl is True
        assert config.port == 636

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_connection_config_validation_missing_server(self) -> None:
        """Test ConnectionConfig validation with missing required field."""
        with pytest.raises(ValidationError):
            FlextLdapModels.ConnectionConfig(
                port=3390,
                base_dn="dc=flext,dc=local",
                # Missing server (required)
            )


class TestFlextLdapModelsSearchRequest:
    """SearchRequest model tests."""

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_search_request_basic_creation(self) -> None:
        """Test creating SearchRequest with required fields."""
        request = FlextLdapModels.SearchRequest(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
        )
        assert request.base_dn == "dc=flext,dc=local"
        assert request.filter_str == "(objectClass=*)"

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_search_request_with_scope(self) -> None:
        """Test SearchRequest with explicit scope."""
        request = FlextLdapModels.SearchRequest(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )
        assert request.scope == "SUBTREE"

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_search_request_with_attributes(self) -> None:
        """Test SearchRequest with specific attributes."""
        request = FlextLdapModels.SearchRequest(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            attributes=["cn", "mail", "objectClass"],
        )
        assert len(request.attributes or []) == 3
        assert "cn" in (request.attributes or [])


class TestFlextLdapModelsSearchWithRealDocker:
    """Real Docker search tests with models."""

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_search_from_real_ldap_server(self) -> None:
        """Test search with real LDAP server data."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True

        # Search
        search_result = client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="BASE",
        )
        assert search_result.is_success is True

        entries = search_result.unwrap()
        assert isinstance(entries, list)
        assert len(entries) > 0

        # Cleanup
        client.unbind()

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_search_empty_results(self) -> None:
        """Test search returning empty results."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True

        # Search for non-existent entries
        search_result = client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(cn=nonexistent12345)",
            scope="SUBTREE",
        )
        assert search_result.is_success is True

        entries = search_result.unwrap()
        assert isinstance(entries, list)
        assert len(entries) == 0

        # Cleanup
        client.unbind()


class TestFlextLdapModelsServerInfo:
    """ServerInfo model tests with real Docker data."""

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_server_type_detection(self) -> None:
        """Test server type detection with real LDAP server."""
        client = FlextLdapClients()

        # Connect
        connect_result = client.connect(
            server_uri="ldap://localhost:3390",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            password="REDACTED_LDAP_BIND_PASSWORD123",
        )
        assert connect_result.is_success is True

        # Get server type
        server_type = client.server_type
        assert isinstance(server_type, str)
        assert len(server_type) > 0

        # Cleanup
        client.unbind()


class TestFlextLdapModelsSerialization:
    """Serialization and deserialization tests for Pydantic v2 models."""

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_connection_config_serialization(self) -> None:
        """Test ConnectionConfig serialization to dict."""
        config = FlextLdapModels.ConnectionConfig(
            server="localhost",
            port=3390,
            base_dn="dc=flext,dc=local",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            bind_password="REDACTED_LDAP_BIND_PASSWORD123",
        )

        # Pydantic v2 serialization
        data = config.model_dump()
        assert isinstance(data, dict)
        assert data["server"] == "localhost"
        assert data["port"] == 3390

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_connection_config_json_serialization(self) -> None:
        """Test ConnectionConfig JSON serialization."""
        config = FlextLdapModels.ConnectionConfig(
            server="localhost",
            port=3390,
            base_dn="dc=flext,dc=local",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            bind_password="REDACTED_LDAP_BIND_PASSWORD123",
        )

        # Pydantic v2 JSON serialization
        json_str = config.model_dump_json()
        assert isinstance(json_str, str)
        assert "localhost" in json_str

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_connection_config_deserialization(self) -> None:
        """Test ConnectionConfig deserialization from dict."""
        data = {
            "server": "localhost",
            "port": 3390,
            "base_dn": "dc=flext,dc=local",
            "bind_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            "bind_password": "REDACTED_LDAP_BIND_PASSWORD123",
        }

        # Pydantic v2 deserialization
        config = FlextLdapModels.ConnectionConfig.model_validate(data)
        assert config.server == "localhost"
        assert config.port == 3390


class TestFlextLdapModelsIntegration:
    """Integration tests with real Docker LDAP operations."""

    @pytest.mark.docker
    @pytest.mark.ldap
    @pytest.mark.unit
    def test_full_search_workflow(self) -> None:
        """Test complete search workflow using FlextLdapModels."""
        # Create connection config
        config = FlextLdapModels.ConnectionConfig(
            server="localhost",
            port=3390,
            base_dn="dc=flext,dc=local",
            bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            bind_password="REDACTED_LDAP_BIND_PASSWORD123",
        )

        # Create search request
        search_req = FlextLdapModels.SearchRequest(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="BASE",
            attributes=["cn", "objectClass"],
        )

        # Execute search
        client = FlextLdapClients()
        connect_result = client.connect(
            server_uri=f"ldap://{config.server}:{config.port}",
            bind_dn=config.bind_dn,
            password=config.bind_password,
        )
        assert connect_result.is_success is True

        search_result = client.search(
            base_dn=search_req.base_dn,
            filter_str=search_req.filter_str,
            scope=search_req.scope,
            attributes=search_req.attributes,
        )
        assert search_result.is_success is True

        entries = search_result.unwrap()
        assert isinstance(entries, list)

        # Cleanup
        client.unbind()


__all__ = [
    "TestFlextLdapModelsConnectionConfig",
    "TestFlextLdapModelsIntegration",
    "TestFlextLdapModelsSearchRequest",
    "TestFlextLdapModelsSearchWithRealDocker",
    "TestFlextLdapModelsSerialization",
    "TestFlextLdapModelsServerInfo",
]

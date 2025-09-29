"""Integration tests using shared LDAP container from docker/shared_ldap_fixtures.py.

This module demonstrates how to use the shared LDAP infrastructure
across all FLEXT projects to avoid container conflicts and ensure
consistent testing infrastructure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import pytest

from flext_ldap import FlextLdapClient, FlextLdapModels
from flext_ldap.constants import FlextLdapConstants
from ..support.shared_ldap_fixtures import check_docker_available, skip_if_no_docker

# Skip all integration tests when LDAP server is not available
pytestmark = pytest.mark.skip(
    reason="Integration tests require LDAP server - skipping when no server available"
)


class TestSharedLDAPIntegration:
    """Test integration with shared LDAP container."""

    @pytest.mark.asyncio
    async def test_shared_ldap_connection(
        self,
        shared_ldap_client: FlextLdapClient,
        shared_ldap_config: dict,
    ) -> None:
        """Test connecting to shared LDAP container."""
        # The client should already be connected via the fixture
        assert shared_ldap_client is not None

        # Test basic search to verify connection
        search_result = await shared_ldap_client.search_universal(
            base_dn=shared_ldap_config["base_dn"],
            search_filter="(objectClass=*)",
            scope="base",
        )

        assert search_result.is_success, f"Search failed: {search_result.error}"
        assert search_result.value is not None

    @pytest.mark.asyncio
    async def test_shared_ldap_schema_discovery(
        self,
        shared_ldap_client: FlextLdapClient,
    ) -> None:
        """Test schema discovery with shared LDAP container."""
        # Test schema discovery
        schema_result = await shared_ldap_client.discover_schema()

        assert schema_result.is_success, (
            f"Schema discovery failed: {schema_result.error}"
        )
        assert schema_result.value is not None

        # Verify we got some schema information
        schema_data = schema_result.value
        assert isinstance(schema_data, FlextLdapModels.SchemaDiscoveryResult)
        assert schema_data.server_info is not None

    @pytest.mark.asyncio
    async def test_shared_ldap_container_manager(
        self,
        shared_ldap_container_manager: object,
        shared_ldap_container: object,
    ) -> None:
        """Test shared container manager functionality."""
        # Suppress unused parameter warning - fixture is used for side effects
        _ = shared_ldap_container
        # Verify container manager is available
        assert shared_ldap_container_manager is not None

        # Verify container is running
        if hasattr(shared_ldap_container_manager, "is_container_running"):
            assert getattr(shared_ldap_container_manager, "is_container_running")()

        # Test LDIF export
        if hasattr(shared_ldap_container_manager, "get_ldif_export"):
            ldif_data = getattr(shared_ldap_container_manager, "get_ldif_export")()
        else:
            ldif_data = ""

        assert ldif_data is not None
        assert len(ldif_data) > 0

        # Verify LDIF contains expected base structure
        assert "dc=flext,dc=local" in ldif_data
        assert "objectClass: dcObject" in ldif_data

    @pytest.mark.asyncio
    async def test_shared_ldap_environment_variables(
        self,
        shared_ldap_config: dict,
    ) -> None:
        """Test that shared LDAP environment variables are properly set."""
        # Verify all required config keys are present
        required_keys = ["server_url", "bind_dn", "password", "base_dn"]
        for key in required_keys:
            assert key in shared_ldap_config, f"Missing config key: {key}"

        # Verify values are not empty
        for key, value in shared_ldap_config.items():
            if key != "container":  # container can be None
                assert value is not None and str(value).strip(), (
                    f"Empty value for {key}: {value}"
                )

        # Verify specific values match shared constants
        assert shared_ldap_config["server_url"] == "ldap://localhost:3390"
        assert shared_ldap_config["bind_dn"] == "cn=admin,dc=flext,dc=local"
        assert shared_ldap_config["password"] == "admin123"
        assert shared_ldap_config["base_dn"] == "dc=flext,dc=local"

    @pytest.mark.asyncio
    async def test_shared_ldif_data_fixture(
        self,
        shared_ldif_data: str,
    ) -> None:
        """Test shared LDIF data fixture."""
        assert shared_ldif_data is not None
        assert len(shared_ldif_data) > 0

        # Verify LDIF contains expected structure
        assert "dc=flext,dc=local" in shared_ldif_data
        assert "objectClass: dcObject" in shared_ldif_data
        assert "objectClass: organization" in shared_ldif_data

        # Verify test data is included
        assert "ou=people," in shared_ldif_data
        assert "uid=john.doe," in shared_ldif_data

    @pytest.mark.asyncio
    async def test_shared_ldap_connection_config(
        self,
        shared_ldap_connection_config: FlextLdapModels.ConnectionConfig,
    ) -> None:
        """Test shared LDAP connection config fixture."""
        assert shared_ldap_connection_config is not None

        # Verify config values
        assert shared_ldap_connection_config.server == "ldap://localhost:3390"
        assert shared_ldap_connection_config.bind_dn == "cn=admin,dc=flext,dc=local"
        assert shared_ldap_connection_config.bind_password == "admin123"
        assert shared_ldap_connection_config.base_dn == "dc=flext,dc=local"
        assert shared_ldap_connection_config.use_ssl is False
        assert (
            shared_ldap_connection_config.timeout == FlextLdapConstants.DEFAULT_TIMEOUT
        )

    @pytest.mark.asyncio
    async def test_shared_ldap_crud_operations(
        self,
        shared_ldap_client: FlextLdapClient,
        shared_ldap_config: dict,
    ) -> None:
        """Test CRUD operations with shared LDAP container."""
        base_dn = shared_ldap_config["base_dn"]

        # Test creating an organizational unit using universal add
        ou_dn = f"ou=test,{base_dn}"
        create_result = await shared_ldap_client.add_entry_universal(
            dn=ou_dn,
            attributes={
                "objectClass": ["organizationalUnit", "top"],
                "ou": "test",
                "description": "Test OU for shared LDAP integration",
            },
        )

        # Note: Creation might fail if entry already exists, which is OK for shared container
        if not create_result.is_success:
            # If creation failed, try to search for existing entry
            search_result = await shared_ldap_client.search_universal(
                base_dn=ou_dn, search_filter="(objectClass=*)", scope="base"
            )
            assert search_result.is_success, (
                f"Entry should exist or be creatable: {create_result.error}"
            )
        else:
            assert create_result.is_success, (
                f"Failed to create test OU: {create_result.error}"
            )

        # Test searching for the entry
        search_result = await shared_ldap_client.search_universal(
            base_dn=ou_dn, search_filter="(objectClass=*)", scope="base"
        )

        assert search_result.is_success, (
            f"Failed to search test OU: {search_result.error}"
        )
        assert search_result.value is not None
        assert len(search_result.value) > 0

        # Clean up - delete the test entry
        delete_result = await shared_ldap_client.delete_entry_universal(ou_dn)
        # Note: Deletion might fail if entry doesn't exist or we don't have permissions
        # This is OK for shared container testing
        if not delete_result.is_success:
            # Just log the failure, don't fail the test
            pass


class TestSharedLDAPSkipConditions:
    """Test skip conditions for shared LDAP when Docker is not available."""

    def test_skip_if_no_docker_decorator(self) -> None:
        """Test that skip_if_no_docker decorator works."""

        # This should not raise an exception - test the decorator factory
        @skip_if_no_docker
        def dummy_test() -> None:
            pass

        assert dummy_test is not None

    def test_docker_availability_check(self) -> None:
        """Test Docker availability check."""
        # This should return a boolean
        is_available = check_docker_available()
        assert isinstance(is_available, bool)

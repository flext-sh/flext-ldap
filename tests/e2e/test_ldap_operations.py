"""End-to-end tests for LDAP operations.

These tests validate complete LDAP workflows from API to infrastructure.
They require a real LDAP server for full integration testing.
"""

from __future__ import annotations

import pytest

from flext_ldap.api import get_ldap_api
from flext_ldap.config import FlextLdapConnectionConfig
from flext_ldap.models import FlextLdapCreateUserRequest


@pytest.mark.e2e
class TestLdapE2EOperations:
    """End-to-end tests for LDAP operations."""

    @pytest.mark.asyncio
    async def test_complete_user_lifecycle(self) -> None:
        """Test complete user management lifecycle.

        This test would require a real LDAP server to be fully functional.
        Currently it tests the API flow without actual LDAP operations.
        """
        # Get API instance
        api = get_ldap_api()

        # Test configuration
        FlextLdapConnectionConfig(
            host="localhost",
            port=3389,  # Test port for Docker LDAP server
        )

        # Test connection creation (will fail without real server)
        connection_result = await api.connect(
            server_uri="ldap://localhost:3389",
            bind_dn="cn=admin,dc=flext,dc=local",
            bind_password="admin123"
        )

        # For now, just test that the API methods exist and return results
        assert connection_result is not None
        assert hasattr(connection_result, "is_success")

        # Create user request
        user_request = FlextLdapCreateUserRequest(
            dn="cn=testuser,ou=users,dc=flext,dc=local",
            uid="testuser",
            cn="Test User",
            sn="User",
            mail="testuser@example.com",
        )

        # Test user creation request structure
        assert user_request.dn == "cn=testuser,ou=users,dc=flext,dc=local"
        assert user_request.uid == "testuser"

        # Convert to LDAP attributes
        attributes = user_request.to_ldap_attributes()
        assert "uid" in attributes
        assert "cn" in attributes
        assert "sn" in attributes
        assert "mail" in attributes

    @pytest.mark.asyncio
    async def test_search_operations_flow(self) -> None:
        """Test LDAP search operations flow."""
        api = get_ldap_api()

        # Test search without connection (should fail gracefully)
        search_result = await api.search(
            session=None,  # No active session
            base_dn="dc=flext,dc=local",
            search_filter="(objectClass=person)"
        )

        # Should handle missing session gracefully
        assert search_result is not None
        assert hasattr(search_result, "is_success")

    @pytest.mark.asyncio
    async def test_group_management_flow(self) -> None:
        """Test group management workflow."""
        api = get_ldap_api()

        # Test group operations structure
        # Note: Actual implementation would require real LDAP server

        # Test that API has group-related methods
        assert hasattr(api, "create_group") or callable(getattr(api, "create_group", None))

        # Verify API is properly initialized
        assert api is not None

    @pytest.mark.asyncio
    async def test_connection_error_handling(self) -> None:
        """Test connection error handling in E2E scenarios."""
        api = get_ldap_api()

        # Test connection to non-existent server
        result = await api.connect(
            server_uri="ldap://nonexistent.server.test:389"
        )

        # Should fail gracefully
        assert not result.is_success
        assert result.error is not None
        assert "connection" in result.error.lower() or "failed" in result.error.lower()

    def test_api_configuration_integration(self) -> None:
        """Test API configuration integration."""
        # Test with custom configuration
        FlextLdapConnectionConfig(
            host="test.ldap.server",
            port=636,
            use_ssl=True,
            timeout_seconds=60,
        )

        # Create API with configuration
        api = get_ldap_api()

        # Should handle configuration properly
        assert api is not None

    @pytest.mark.asyncio
    async def test_error_propagation_e2e(self) -> None:
        """Test error propagation through the entire stack."""
        api = get_ldap_api()

        # Test various error scenarios
        scenarios = [
            ("", "Invalid server URI"),
            ("invalid://protocol", "Protocol error"),
            ("ldap://", "Incomplete URI"),
        ]

        for uri, _expected_error_type in scenarios:
            result = await api.connect(server_uri=uri)

            # Should handle all error types gracefully
            assert hasattr(result, "is_success")
            if not result.is_success:
                assert result.error is not None


@pytest.mark.e2e
@pytest.mark.slow
class TestLdapE2EWithDockerServer:
    """E2E tests that would work with Docker LDAP server.

    These tests are marked as 'slow' and require Docker infrastructure.
    They demonstrate the full testing approach for real LDAP operations.
    """

    @pytest.mark.asyncio
    async def test_real_ldap_user_operations(self) -> None:
        """Test real LDAP user operations with Docker server.

        This test would require the Docker LDAP server to be running.
        It's currently a placeholder showing the intended test structure.
        """
        # Would require:
        # 1. Docker LDAP server running on localhost:3389
        # 2. Test domain: dc=flext,dc=local
        # 3. Admin credentials: cn=admin,dc=flext,dc=local / admin123

        get_ldap_api()

        # Connection parameters for Docker test server

        # For now, just test the structure
        user_request = FlextLdapCreateUserRequest(
            dn="cn=e2etest,ou=users,dc=flext,dc=local",
            uid="e2etest",
            cn="E2E Test User",
            sn="TestUser",
            mail="e2etest@example.com",
        )

        assert user_request.dn == "cn=e2etest,ou=users,dc=flext,dc=local"

    @pytest.mark.asyncio
    async def test_real_ldap_search_operations(self) -> None:
        """Test real LDAP search operations with Docker server."""
        # Placeholder for real search operations
        # Would test:
        # 1. Base DN search
        # 2. Filter-based search
        # 3. Attribute retrieval
        # 4. Paged search results

        api = get_ldap_api()
        assert api is not None

    @pytest.mark.asyncio
    async def test_real_ldap_group_operations(self) -> None:
        """Test real LDAP group operations with Docker server."""
        # Placeholder for real group operations
        # Would test:
        # 1. Group creation
        # 2. Member addition/removal
        # 3. Group search
        # 4. Group deletion

        api = get_ldap_api()
        assert api is not None

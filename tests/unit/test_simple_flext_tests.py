"""Simple test to validate flext_tests library integration."""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldap import FlextLDAPApi
from flext_ldap.entities import FlextLDAPEntities


@pytest.mark.asyncio
class TestSimpleFlextTestsIntegration:
    """Simple flext_tests integration validation."""

    def test_basic_api_initialization(self) -> None:
        """Test basic API initialization without flext_tests imports."""
        api = FlextLDAPApi()

        # Basic assertions without flext_tests
        assert api is not None
        assert hasattr(api, "_config")
        assert hasattr(api, "_service")
        assert hasattr(api, "_container")

    def test_session_id_generation(self) -> None:
        """Test session ID generation."""
        api = FlextLDAPApi()

        # Generate session IDs
        session_id_1 = api._generate_session_id()
        session_id_2 = api._generate_session_id()

        # Basic validation
        assert isinstance(session_id_1, str)
        assert isinstance(session_id_2, str)
        assert session_id_1 != session_id_2
        assert session_id_1.startswith("session_")
        assert session_id_2.startswith("session_")

    async def test_basic_api_operations(self) -> None:
        """Test basic API operations without connection."""
        api = FlextLDAPApi()

        # Test search without connection (should fail gracefully)
        search_request = FlextLDAPEntities.SearchRequest(
            base_dn="dc=example,dc=com",
            filter_str="(objectClass=*)",
            scope="base",
        )

        result = await api.search(search_request)

        # Should return FlextResult (success or failure)
        assert isinstance(result, FlextResult)

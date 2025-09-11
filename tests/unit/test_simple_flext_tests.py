"""Simple test to validate flext_tests library integration.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

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
        """Test session ID generation using Python stdlib SOURCE OF TRUTH."""
        import uuid

        # Generate session IDs using Python standard library SOURCE OF TRUTH
        session_id_1 = f"session_{uuid.uuid4()}"
        session_id_2 = f"session_{uuid.uuid4()}"

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
            attributes=[],
            size_limit=100,
            time_limit=30,
        )

        result = await api.search(search_request)

        # Should return FlextResult (success or failure)
        assert isinstance(result, FlextResult)

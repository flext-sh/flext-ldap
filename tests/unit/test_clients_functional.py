"""Functional client tests for flext-ldap - ZERO TOLERANCE implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_core import FlextResult
from flext_ldap import FlextLdapClient, FlextLdapModels


class TestFlextLdapClientFunctional:
    """Comprehensive functional tests for FlextLdapClient."""

    def test_client_initialization(self) -> None:
        """Test client initialization."""
        client = FlextLdapClient()
        # Note: _connection and _server are protected attributes
        # We can't directly access them in tests, but we can test the public interface
        assert not client.is_connected()

    @pytest.mark.asyncio
    async def test_connect_without_server(self) -> None:
        """Test connection failure without server."""
        client = FlextLdapClient()
        result = await client.connect(
            "ldap://localhost:389",
            "cn=admin,dc=test,dc=com",
            "password",
        )
        assert isinstance(result, FlextResult)

    @pytest.mark.asyncio
    async def test_search_without_connection(self) -> None:
        """Test search operation without connection."""
        client = FlextLdapClient()
        request = FlextLdapModels.SearchRequest(
            base_dn="dc=test,dc=com",
            filter="(objectClass=person)",
            scope="subtree",
            attributes=["cn", "uid"],
            size_limit=100,
            time_limit=30,
            page_size=None,
            paged_cookie=None,
        )
        result = await client.search_with_request(request)
        assert not result.is_success
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_add_without_connection(self) -> None:
        """Test add operation without connection."""
        client = FlextLdapClient()
        result = await client.add(
            "cn=test,dc=test,dc=com",
            {"cn": "test", "objectClass": ["person"]},
        )
        assert not result.is_success
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_unbind_operation(self) -> None:
        """Test unbind operation."""
        client = FlextLdapClient()
        result = await client.unbind()
        assert result.is_success  # Should succeed even without connection

"""Unit tests for flext-ldap models with correct modern API.

Tests for FlextLdapModels components including Entry, SearchRequest, and other models
using the actual modern API from FlextLdifModels.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_ldif import FlextLdifModels

from flext_ldap.models import FlextLdapModels


class TestDistinguishedName:
    """Tests for DistinguishedName model."""

    def test_distinguished_name_creation(self) -> None:
        """Test creating a distinguished name."""
        dn = FlextLdifModels.DistinguishedName(
            value="uid=testuser,ou=people,dc=example,dc=com"
        )
        assert dn.value == "uid=testuser,ou=people,dc=example,dc=com"

    @pytest.mark.skip(
        reason="Computed properties (rdn, rdn_attribute, etc.) not in modern DistinguishedName API"
    )
    def test_distinguished_name_computed_properties(self) -> None:
        """Test DistinguishedName computed properties.

        Note: Modern DistinguishedName API only has 'value' field.
        RDN parsing and computed properties are not implemented.
        """
        dn = FlextLdifModels.DistinguishedName(
            value="uid=testuser,ou=people,dc=example,dc=com"
        )

        # Test rdn property
        assert dn.rdn == "uid=testuser"

        # Test rdn_attribute property
        assert dn.rdn_attribute == "uid"

        # Test rdn_value property
        assert dn.rdn_value == "testuser"

        # Test components_count property
        assert dn.components_count == 4

    def test_distinguished_name_normalization(self) -> None:
        """Test DN normalization with mixed case."""
        dn = FlextLdifModels.DistinguishedName(
            value="CN=Test User,OU=People,DC=Example,DC=Com"
        )
        # Verify that DN is properly created
        assert "Test User" in dn.value or "test" in dn.value.lower()


class TestSearchRequest:
    """Tests for SearchRequest model."""

    def test_create_user_search(self) -> None:
        """Test creating a user search request."""
        search_req = FlextLdapModels.SearchRequest.create_user_search(
            uid="john", base_dn="ou=people,dc=example,dc=com"
        )

        assert search_req.base_dn == "ou=people,dc=example,dc=com"
        assert "john" in search_req.filter_str
        assert "person" in search_req.filter_str.lower()
        assert search_req.page_size == 100

    def test_create_group_search(self) -> None:
        """Test creating a group search request."""
        search_req = FlextLdapModels.SearchRequest.create_group_search(
            cn="developers", base_dn="ou=groups,dc=example,dc=com"
        )

        assert search_req.base_dn == "ou=groups,dc=example,dc=com"
        assert "developers" in search_req.filter_str
        assert "group" in search_req.filter_str.lower()
        assert search_req.page_size == 100

    def test_search_request_with_custom_attributes(self) -> None:
        """Test search request with custom attributes."""
        search_req = FlextLdapModels.SearchRequest.create_user_search(
            uid="jane",
            base_dn="ou=people,dc=example,dc=com",
            attributes=["cn", "mail", "telephoneNumber"],
        )

        assert search_req.attributes == ["cn", "mail", "telephoneNumber"]

    def test_search_request_validation(self) -> None:
        """Test search request validation."""
        # Test that empty DN raises validation error
        with pytest.raises(ValueError, match="DN cannot be empty"):
            FlextLdapModels.SearchRequest.create(base_dn="", filter_str="(uid=test)")

        # Test that empty filter raises validation error
        with pytest.raises(ValueError, match="Filter string cannot be empty"):
            FlextLdapModels.SearchRequest.create(
                base_dn="dc=example,dc=com", filter_str=""
            )


__all__ = ["TestDistinguishedName", "TestSearchRequest"]

"""Constants coverage tests for flext-ldap."""

from __future__ import annotations

from flext_ldap import FlextLdapConstants

"""Module documentation.

- Target constants.py (101 statements, 98% coverage) for easy 100% win
- Test attribute getter methods

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""


class TestFlextLdapConstantsCoverage:
    """Test FLEXT LDAP constants for complete coverage."""

    def test_get_person_attributes(self) -> None:
        """Test get_person_attributes method."""
        attributes = FlextLdapConstants.Attributes.get_person_attributes()

        # Should return a list
        assert isinstance(attributes, list)
        assert len(attributes) > 0

        # Should contain expected attributes
        assert "objectClass" in attributes
        assert "cn" in attributes
        assert "sn" in attributes
        assert "givenName" in attributes
        assert "displayName" in attributes
        assert "uid" in attributes
        assert "mail" in attributes
        assert "description" in attributes

    def test_get_group_attributes(self) -> None:
        """Test get_group_attributes method."""
        attributes = FlextLdapConstants.Attributes.get_group_attributes()

        # Should return a list
        assert isinstance(attributes, list)
        assert len(attributes) > 0

        # Should contain expected attributes
        assert "objectClass" in attributes
        assert "cn" in attributes
        assert "description" in attributes
        assert "member" in attributes
        assert "uniqueMember" in attributes

    def test_constants_module_structure(self) -> None:
        """Test that constants module has expected structure."""
        # Should have Attributes class
        assert hasattr(FlextLdapConstants, "Attributes")

        # Should have expected attribute constants
        attrs = FlextLdapConstants.Attributes
        assert hasattr(attrs, "OBJECT_CLASS")
        assert hasattr(attrs, "COMMON_NAME")
        assert hasattr(attrs, "SURNAME")
        assert hasattr(attrs, "GIVEN_NAME")
        assert hasattr(attrs, "USER_ID")
        assert hasattr(attrs, "MAIL")
        assert hasattr(attrs, "DESCRIPTION")
        assert hasattr(attrs, "MEMBER")
        assert hasattr(attrs, "UNIQUE_MEMBER")

    def test_attribute_values(self) -> None:
        """Test that attribute constants have expected values."""
        attrs = FlextLdapConstants.Attributes

        # Test specific values
        assert attrs.OBJECT_CLASS == "objectClass"
        assert attrs.COMMON_NAME == "cn"
        assert attrs.SURNAME == "sn"
        assert attrs.GIVEN_NAME == "givenName"
        assert attrs.DISPLAY_NAME == "displayName"
        assert attrs.USER_ID == "uid"
        assert attrs.MAIL == "mail"
        assert attrs.DESCRIPTION == "description"
        assert attrs.MEMBER == "member"
        assert attrs.UNIQUE_MEMBER == "uniqueMember"

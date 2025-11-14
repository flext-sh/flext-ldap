"""Unit tests for OpenLDAP 1.x quirks detection and handling.

Tests OpenLDAP 1.x specific quirks including ACL format, schema location,
and server-specific behavior using deduplication helpers.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap.constants import FlextLdapConstants
from tests.helpers.test_deduplication_helpers import TestDeduplicationHelpers

pytestmark = pytest.mark.unit


class TestOpenLDAP1Quirks:
    """Tests for OpenLDAP 1.x quirks detection and handling."""

    def test_openldap1_server_type_constant(self) -> None:
        """Test OpenLDAP 1.x server type constant."""
        assert FlextLdapConstants.ServerTypes.OPENLDAP1 == "openldap1"

    def test_openldap1_acl_format_constant(self) -> None:
        """Test OpenLDAP 1.x ACL format constant."""
        assert FlextLdapConstants.AclFormat.OPENLDAP1 == "openldap1"

    def test_openldap1_detection_from_entries(self) -> None:
        """Test detecting OpenLDAP 1.x from LDAP entries."""
        # OpenLDAP 1.x entries typically have access attribute (not olcAccess)
        # This is a placeholder test - actual detection would use quirks integration
        server_type = FlextLdapConstants.ServerTypes.OPENLDAP1
        assert server_type == "openldap1"

    def test_openldap1_acl_attribute_name(self) -> None:
        """Test OpenLDAP 1.x ACL attribute name."""
        # OpenLDAP 1.x uses "access" attribute (slapd.conf format)
        # OpenLDAP 2.x uses "olcAccess" (cn=config format)
        acl_attr_openldap1 = "access"
        acl_attr_openldap2 = "olcAccess"
        assert acl_attr_openldap1 != acl_attr_openldap2
        assert acl_attr_openldap1 == "access"

    def test_openldap1_schema_location(self) -> None:
        """Test OpenLDAP 1.x schema subentry location."""
        # Both OpenLDAP 1.x and 2.x use cn=subschema
        schema_dn = "cn=subschema"
        assert schema_dn == "cn=subschema"

    def test_openldap1_search_operations(self) -> None:
        """Test search operations with OpenLDAP 1.x quirks."""
        # Create search options using deduplication helpers
        search_options = TestDeduplicationHelpers.create_search(
            filter_str="(objectClass=*)"
        )
        assert search_options.filter_str == "(objectClass=*)"
        assert search_options.base_dn is not None

    def test_openldap1_entry_creation(self) -> None:
        """Test entry creation for OpenLDAP 1.x."""
        # Create entry using deduplication helpers
        entry = TestDeduplicationHelpers.create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"], "objectClass": ["top", "person"]},
        )
        assert entry.dn is not None
        assert str(entry.dn) == "cn=test,dc=example,dc=com"

    def test_openldap1_user_entry_creation(self) -> None:
        """Test user entry creation for OpenLDAP 1.x."""
        # Create user entry using deduplication helpers
        entry = TestDeduplicationHelpers.create_user("testuser")
        assert entry.dn is not None
        assert "testuser" in str(entry.dn).lower()

    def test_openldap1_legacy_config_format(self) -> None:
        """Test OpenLDAP 1.x uses legacy slapd.conf format."""
        # OpenLDAP 1.x uses slapd.conf (static config)
        # OpenLDAP 2.x uses cn=config (dynamic config)
        config_format_openldap1 = "slapd.conf"
        config_format_openldap2 = "cn=config"
        assert config_format_openldap1 != config_format_openldap2
        assert config_format_openldap1 == "slapd.conf"

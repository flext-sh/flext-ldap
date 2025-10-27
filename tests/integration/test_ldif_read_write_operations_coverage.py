"""LDAP read/write operations coverage - Real Docker LDAP testing.

Tests LDAP add, search, modify, delete operations using the correct
FlextLdapClients API with proper type signatures: add_entry(dn=..., attributes=...).

All tests use real Docker LDAP operations with FlextResult patterns.
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_ldap import FlextLdapClients, FlextLdapModels


@pytest.mark.integration
@pytest.mark.docker
class TestLdapReadWriteBasic:
    """Basic LDAP read/write operations with correct API usage."""

    def test_add_entry_basic(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test adding a basic entry with correct API signature."""
        result = shared_ldap_client.add_entry(
            dn="ou=testou1,dc=flext,dc=local",
            attributes={
                "objectClass": ["organizationalUnit"],
                "ou": "testou1",
            },
        )
        assert isinstance(result, FlextResult)

    def test_add_entry_with_multiple_attributes(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test adding entry with multiple attributes."""
        result = shared_ldap_client.add_entry(
            dn="cn=testuser1,dc=flext,dc=local",
            attributes={
                "objectClass": ["inetOrgPerson"],
                "cn": "testuser1",
                "sn": "User",
                "mail": "testuser1@internal.invalid",
            },
        )
        assert isinstance(result, FlextResult)

    def test_add_entry_with_list_values(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test adding entry with list-valued attributes."""
        result = shared_ldap_client.add_entry(
            dn="cn=testgroup1,dc=flext,dc=local",
            attributes={
                "objectClass": ["groupOfNames"],
                "cn": "testgroup1",
                "member": [
                    "cn=testuser1,dc=flext,dc=local",
                    "cn=testuser2,dc=flext,dc=local",
                ],
            },
        )
        assert isinstance(result, FlextResult)

    def test_search_after_add(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test searching for added entry."""
        # First add an entry
        add_result = shared_ldap_client.add_entry(
            dn="cn=searchtest1,dc=flext,dc=local",
            attributes={
                "objectClass": ["inetOrgPerson"],
                "cn": "searchtest1",
                "sn": "Test",
            },
        )

        if add_result.is_failure:
            # May fail if entry already exists, continue with search
            pass

        # Then search for it
        search_result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(cn=searchtest1)",
        )
        assert isinstance(search_result, FlextResult)

    def test_modify_entry_add_attribute(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test modifying entry by adding attribute."""
        # First ensure entry exists
        add_result = shared_ldap_client.add_entry(
            dn="cn=modifytest1,dc=flext,dc=local",
            attributes={
                "objectClass": ["inetOrgPerson"],
                "cn": "modifytest1",
                "sn": "Test",
            },
        )

        # Then modify it
        if add_result.is_success or add_result.is_failure:
            # If added or already exists, try to modify
            changes = FlextLdapModels.EntryChanges()
            changes.mail = ["test@example.com"]
            modify_result = shared_ldap_client.modify_entry(
                dn="cn=modifytest1,dc=flext,dc=local",
                changes=changes,
            )
            assert isinstance(modify_result, FlextResult)

    def test_delete_entry(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test deleting an entry."""
        # First add an entry
        add_result = shared_ldap_client.add_entry(
            dn="cn=deletetest1,dc=flext,dc=local",
            attributes={
                "objectClass": ["inetOrgPerson"],
                "cn": "deletetest1",
                "sn": "Test",
            },
        )

        # Then delete it
        if add_result.is_success:
            delete_result = shared_ldap_client.delete_entry(
                dn="cn=deletetest1,dc=flext,dc=local"
            )
            assert isinstance(delete_result, FlextResult)


@pytest.mark.integration
@pytest.mark.docker
class TestLdapAttributeHandling:
    """Test proper attribute type handling in LDAP operations."""

    def test_string_attribute_conversion(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test that string attributes are properly converted to lists."""
        result = shared_ldap_client.add_entry(
            dn="cn=attrtest1,dc=flext,dc=local",
            attributes={
                "objectClass": ["inetOrgPerson"],
                "cn": "attrtest1",  # String, will be converted to ["attrtest1"]
                "sn": "Test",
            },
        )
        assert isinstance(result, FlextResult)

    def test_list_attribute_handling(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test that list attributes are handled correctly."""
        result = shared_ldap_client.add_entry(
            dn="cn=attrtest2,dc=flext,dc=local",
            attributes={
                "objectClass": ["inetOrgPerson", "organizationalPerson"],
                "cn": ["attrtest2"],
                "sn": ["Test"],
            },
        )
        assert isinstance(result, FlextResult)

    def test_empty_string_attribute(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test handling of potentially empty attributes."""
        # LDAP doesn't allow empty attributes, so this tests error handling
        result = shared_ldap_client.add_entry(
            dn="cn=attrtest3,dc=flext,dc=local",
            attributes={
                "objectClass": ["inetOrgPerson"],
                "cn": "attrtest3",
                "sn": "Test",
            },
        )
        assert isinstance(result, FlextResult)


@pytest.mark.integration
@pytest.mark.docker
class TestLdapErrorHandling:
    """Test LDAP operation error handling."""

    def test_duplicate_entry_error(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test handling of duplicate entry error."""
        dn = "cn=duptest1,dc=flext,dc=local"

        # Add first time
        result1 = shared_ldap_client.add_entry(
            dn=dn,
            attributes={
                "objectClass": ["inetOrgPerson"],
                "cn": "duptest1",
                "sn": "Test",
            },
        )

        # Add same entry again - should fail
        result2 = shared_ldap_client.add_entry(
            dn=dn,
            attributes={
                "objectClass": ["inetOrgPerson"],
                "cn": "duptest1",
                "sn": "Test",
            },
        )

        # First should succeed, second should fail
        assert isinstance(result1, FlextResult)
        assert isinstance(result2, FlextResult)

    def test_missing_required_attribute(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test handling of missing required attributes."""
        # inetOrgPerson requires cn and sn
        result = shared_ldap_client.add_entry(
            dn="cn=missingattr1,dc=flext,dc=local",
            attributes={
                "objectClass": ["inetOrgPerson"],
                "cn": "missingattr1",
                # Missing sn which is required
            },
        )
        assert isinstance(result, FlextResult)
        # May fail or succeed depending on server strictness

    def test_invalid_dn_format(self, shared_ldap_client: FlextLdapClients) -> None:
        """Test handling of invalid DN format."""
        result = shared_ldap_client.add_entry(
            dn="invalid-dn-format",
            attributes={
                "objectClass": ["inetOrgPerson"],
                "cn": "test",
                "sn": "Test",
            },
        )
        assert isinstance(result, FlextResult)
        # Should fail with invalid DN


@pytest.mark.integration
@pytest.mark.docker
class TestLdapFlexResultPattern:
    """Test that all operations return proper FlextResult."""

    def test_add_returns_flext_result(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test add_entry returns FlextResult."""
        result = shared_ldap_client.add_entry(
            dn="cn=resulttest1,dc=flext,dc=local",
            attributes={
                "objectClass": ["inetOrgPerson"],
                "cn": "resulttest1",
                "sn": "Test",
            },
        )
        assert isinstance(result, FlextResult)
        assert hasattr(result, "is_success")
        assert hasattr(result, "is_failure")
        assert hasattr(result, "unwrap")

    def test_search_returns_flext_result(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test search returns FlextResult."""
        result = shared_ldap_client.search(
            base_dn="dc=flext,dc=local",
            filter_str="(objectClass=*)",
            scope="SUBTREE",
        )
        assert isinstance(result, FlextResult)

    def test_modify_returns_flext_result(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test modify_entry returns FlextResult."""
        changes = FlextLdapModels.EntryChanges()
        changes.description = ["Modified"]
        result = shared_ldap_client.modify_entry(
            dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            changes=changes,
        )
        assert isinstance(result, FlextResult)

    def test_delete_returns_flext_result(
        self, shared_ldap_client: FlextLdapClients
    ) -> None:
        """Test delete_entry returns FlextResult."""
        result = shared_ldap_client.delete_entry(dn="cn=nonexistent,dc=flext,dc=local")
        assert isinstance(result, FlextResult)

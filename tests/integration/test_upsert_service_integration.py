"""Integration tests for FlextLdapUpsertService with real Docker LDAP.

Comprehensive integration tests for FlextLdapUpsertService using actual
Docker LDAP containers and real LDAP operations (no mocks).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldap import FlextLdap, FlextLdapUpsertService


@pytest.mark.integration
@pytest.mark.docker
class TestUpsertServiceIntegration:
    """Test UPSERT service with real Docker LDAP container using modern API."""

    def test_upsert_entry_add_success_new_entry(
        self, shared_ldap_config: dict[str, str]
    ) -> None:
        """Test successful ADD when entry doesn't exist (new entry) with real LDAP."""
        api = FlextLdap()
        service = FlextLdapUpsertService()

        # Use modern API to upsert new entry
        result = service.upsert_entry(
            ldap_client=api,
            dn="cn=testuser1,ou=users,dc=flext,dc=local",
            new_attributes={
                "cn": ["testuser1"],
                "mail": ["testuser1@example.com"],
                "objectClass": ["inetOrgPerson"],
                "sn": ["User"],
            },
        )

        # Should succeed with ADD
        assert result.is_success
        data = result.unwrap()
        assert data["upserted"] is True
        assert data["added"] >= 3
        assert data["replaced"] == 0

        # Verify entry was created by searching with modern API
        search_result = api.search(
            base_dn="cn=testuser1,ou=users,dc=flext,dc=local",
            search_filter="(cn=testuser1)",
            bulk=False,
        )
        assert search_result.is_success

    def test_upsert_entry_modify_add_new_attributes(
        self, shared_ldap_config: dict[str, str]
    ) -> None:
        """Test modifying existing entry to ADD new attributes with real LDAP."""
        api = FlextLdap()
        service = FlextLdapUpsertService()

        # First, create an entry with minimal attributes
        dn = "cn=testuser2,ou=users,dc=flext,dc=local"
        add_result = api.add_entry(
            dn=dn,
            attributes={
                "cn": "testuser2",
                "objectClass": ["inetOrgPerson"],
                "sn": "User",
            },
        )
        assert add_result.is_success

        # Now UPSERT with additional attributes
        result = service.upsert_entry(
            ldap_client=api,
            dn=dn,
            new_attributes={
                "cn": ["testuser2"],
                "mail": ["testuser2@example.com"],
                "telephoneNumber": ["+1-555-1234"],
                "objectClass": ["inetOrgPerson"],
                "sn": ["User"],
            },
        )

        # Should succeed with ADD of new attributes
        assert result.is_success
        data = result.unwrap()
        assert data["upserted"] is True
        assert data["added"] >= 2

    def test_upsert_entry_modify_replace_attributes(
        self, shared_ldap_config: dict[str, str]
    ) -> None:
        """Test modifying existing entry to REPLACE attribute values with real LDAP."""
        api = FlextLdap()
        service = FlextLdapUpsertService()

        # First, create an entry
        dn = "cn=testuser3,ou=users,dc=flext,dc=local"
        add_result = api.add_entry(
            dn=dn,
            attributes={
                "cn": "testuser3",
                "mail": "oldmail@example.com",
                "objectClass": ["inetOrgPerson"],
                "sn": "User",
            },
        )
        assert add_result.is_success

        # UPSERT with updated mail attribute
        result = service.upsert_entry(
            ldap_client=api,
            dn=dn,
            new_attributes={
                "cn": ["testuser3"],
                "mail": ["newmail@example.com"],
                "objectClass": ["inetOrgPerson"],
                "sn": ["User"],
            },
        )

        # Should succeed with REPLACE of mail attribute
        assert result.is_success
        data = result.unwrap()
        assert data["upserted"] is True
        assert data["replaced"] >= 1

    def test_upsert_entry_skip_attributes(
        self, shared_ldap_config: dict[str, str]
    ) -> None:
        """Test that skip_attributes are honored with real LDAP."""
        api = FlextLdap()
        service = FlextLdapUpsertService()

        # Create entry with cn
        dn = "cn=testuser4,ou=users,dc=flext,dc=local"
        add_result = api.add_entry(
            dn=dn,
            attributes={
                "cn": "testuser4",
                "objectClass": ["inetOrgPerson"],
                "sn": "User",
            },
        )
        assert add_result.is_success

        # UPSERT with skip_attributes including cn
        skip_attrs = {"cn", "objectClass", "sn"}
        result = service.upsert_entry(
            ldap_client=api,
            dn=dn,
            new_attributes={
                "cn": ["testuser4_modified"],
                "mail": ["testuser4@example.com"],
                "objectClass": ["inetOrgPerson"],
                "sn": ["User_modified"],
            },
            skip_attributes=skip_attrs,
        )

        # Should succeed
        assert result.is_success
        data = result.unwrap()
        assert data["upserted"] is True
        assert data["added"] >= 1

    def test_upsert_entry_no_changes_needed(
        self, shared_ldap_config: dict[str, str]
    ) -> None:
        """Test UPSERT when attributes are already correct with real LDAP."""
        api = FlextLdap()
        service = FlextLdapUpsertService()

        # Create entry with specific attributes
        dn = "cn=testuser5,ou=users,dc=flext,dc=local"
        attrs = {
            "cn": "testuser5",
            "mail": "testuser5@example.com",
            "objectClass": ["inetOrgPerson"],
            "sn": "User",
        }
        add_result = api.add_entry(dn=dn, attributes=attrs)
        assert add_result.is_success

        # UPSERT with same attributes
        result = service.upsert_entry(
            ldap_client=api,
            dn=dn,
            new_attributes={
                "cn": ["testuser5"],
                "mail": ["testuser5@example.com"],
                "objectClass": ["inetOrgPerson"],
                "sn": ["User"],
            },
        )

        # Should succeed
        assert result.is_success
        data = result.unwrap()
        assert data["upserted"] is True
        assert data["unchanged"] >= 2

    def test_upsert_entry_multiple_operations(
        self, shared_ldap_config: dict[str, str]
    ) -> None:
        """Test multiple UPSERT operations sequentially with real LDAP."""
        api = FlextLdap()
        service = FlextLdapUpsertService()

        # Create and update same entry multiple times
        dn = "cn=testuser6,ou=users,dc=flext,dc=local"

        # First upsert - add new entry
        result1 = service.upsert_entry(
            ldap_client=api,
            dn=dn,
            new_attributes={
                "cn": ["testuser6"],
                "objectClass": ["inetOrgPerson"],
                "sn": ["User"],
            },
        )
        assert result1.is_success
        assert result1.unwrap()["added"] >= 2

        # Second upsert - add mail
        result2 = service.upsert_entry(
            ldap_client=api,
            dn=dn,
            new_attributes={
                "cn": ["testuser6"],
                "mail": ["testuser6@example.com"],
                "objectClass": ["inetOrgPerson"],
                "sn": ["User"],
            },
        )
        assert result2.is_success
        assert result2.unwrap()["added"] >= 1

        # Third upsert - update mail
        result3 = service.upsert_entry(
            ldap_client=api,
            dn=dn,
            new_attributes={
                "cn": ["testuser6"],
                "mail": ["newemail@example.com"],
                "objectClass": ["inetOrgPerson"],
                "sn": ["User"],
            },
        )
        assert result3.is_success
        assert result3.unwrap()["replaced"] >= 1

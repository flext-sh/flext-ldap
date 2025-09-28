"""Real LDAP repository integration tests using Docker container.

This module tests repository operations against a real OpenLDAP server,
validating CRUD operations, search functionality, and business logic.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldap import FlextLdapClient, FlextLdapModels, FlextLdapRepositories

# Skip all integration tests when LDAP server is not available
pytestmark = pytest.mark.skip(
    reason="Integration tests require LDAP server - skipping when no server available"
)


@pytest.mark.integration
@pytest.mark.asyncio
class TestRealUserRepository:
    """Test real user repository operations."""

    async def test_create_user_in_real_ldap(
        self, shared_ldap_client: FlextLdapClient
    ) -> None:
        """Test creating a user in shared LDAP server."""
        client = shared_ldap_client

        await client.add_entry_universal(
            dn="ou=users,dc=flext,dc=local",
            attributes={"objectClass": ["organizationalUnit"], "ou": "users"},
        )

        repo = FlextLdapRepositories.UserRepository(client=client)

        user = FlextLdapModels.LdapUser(
            dn="cn=testuser,ou=users,dc=flext,dc=local",
            cn="testuser",
            sn="User",
            given_name="Test",
            telephone_number="555-1234",
            mobile="555-5678",
            department="IT",
            title="Software Engineer",
            organization="Flext Inc",
            organizational_unit="Engineering",
            uid="testuser",
            mail="testuser@internal.invalid",
            user_password="testpass123",
        )

        result = await repo.save(user)

        assert result.is_success, f"User creation failed: {result.error}"

        await client.delete_entry_universal(dn="cn=testuser,ou=users,dc=flext,dc=local")
        await client.delete_entry_universal(dn="ou=users,dc=flext,dc=local")

    async def test_get_user_from_real_ldap(
        self, shared_ldap_client: FlextLdapClient
    ) -> None:
        """Test retrieving a user from shared LDAP server."""
        client = shared_ldap_client

        await client.add_entry_universal(
            dn="ou=users,dc=flext,dc=local",
            attributes={"objectClass": ["organizationalUnit"], "ou": "users"},
        )

        await client.add_entry_universal(
            dn="cn=getuser,ou=users,dc=flext,dc=local",
            attributes={
                "objectClass": ["inetOrgPerson"],
                "cn": "getuser",
                "sn": "GetUser",
                "uid": "getuser",
                "mail": "getuser@internal.invalid",
            },
        )

        repo = FlextLdapRepositories.UserRepository(client=client)

        result = await repo.find_by_dn("cn=getuser,ou=users,dc=flext,dc=local")

        assert result.is_success, f"User retrieval failed: {result.error}"
        assert result.value is not None
        user = result.value
        assert hasattr(user, "cn") and user.cn == "getuser"
        assert hasattr(user, "uid") and user.uid == "getuser"

        await client.delete_entry_universal(dn="cn=getuser,ou=users,dc=flext,dc=local")
        await client.delete_entry_universal(dn="ou=users,dc=flext,dc=local")

    async def test_update_user_in_real_ldap(
        self, shared_ldap_client: FlextLdapClient
    ) -> None:
        """Test updating a user in shared LDAP server."""
        client = shared_ldap_client

        await client.add_entry_universal(
            dn="ou=users,dc=flext,dc=local",
            attributes={"objectClass": ["organizationalUnit"], "ou": "users"},
        )

        await client.add_entry_universal(
            dn="cn=updateuser,ou=users,dc=flext,dc=local",
            attributes={
                "objectClass": ["inetOrgPerson"],
                "cn": "updateuser",
                "sn": "UpdateUser",
                "uid": "updateuser",
                "mail": "old@internal.invalid",
            },
        )

        repo = FlextLdapRepositories.UserRepository(client=client)

        user = FlextLdapModels.LdapUser(
            dn="cn=updateuser,ou=users,dc=flext,dc=local",
            cn="updateuser",
            sn="UpdateUser",
            given_name="Update",
            telephone_number="555-9999",
            mobile="555-8888",
            department="IT",
            title="Senior Engineer",
            organization="Flext Inc",
            organizational_unit="Engineering",
            uid="updateuser",
            mail="new@internal.invalid",
            user_password="updatepass123",
        )

        result = await repo.save(user)

        assert result.is_success, f"User update failed: {result.error}"

        search_result = await client.search(
            base_dn="cn=updateuser,ou=users,dc=flext,dc=local",
            filter_str="(objectClass=inetOrgPerson)",
            attributes=["mail"],
        )

        assert search_result.is_success
        assert len(search_result.unwrap()) > 0
        assert "new@internal.invalid" in str(search_result.unwrap()[0].get("mail", ""))

        await client.delete_entry_universal(
            dn="cn=updateuser,ou=users,dc=flext,dc=local"
        )
        await client.delete_entry_universal(dn="ou=users,dc=flext,dc=local")

    async def test_delete_user_from_real_ldap(
        self, shared_ldap_client: FlextLdapClient
    ) -> None:
        """Test deleting a user from real LDAP server."""
        client = shared_ldap_client

        await client.add_entry_universal(
            dn="ou=users,dc=flext,dc=local",
            attributes={"objectClass": ["organizationalUnit"], "ou": "users"},
        )

        await client.add_entry_universal(
            dn="cn=deleteuser,ou=users,dc=flext,dc=local",
            attributes={
                "objectClass": ["inetOrgPerson"],
                "cn": "deleteuser",
                "sn": "DeleteUser",
                "uid": "deleteuser",
                "mail": "deleteuser@internal.invalid",
            },
        )

        repo = FlextLdapRepositories.UserRepository(client=client)

        result = await repo.delete("cn=deleteuser,ou=users,dc=flext,dc=local")

        assert result.is_success, f"User deletion failed: {result.error}"

        search_result = await client.search(
            base_dn="ou=users,dc=flext,dc=local",
            filter_str="(cn=deleteuser)",
        )

        assert search_result.is_success
        assert len(search_result.unwrap()) == 0

        await client.delete_entry_universal(dn="ou=users,dc=flext,dc=local")

    async def test_search_users_in_real_ldap(
        self, shared_ldap_client: FlextLdapClient
    ) -> None:
        """Test searching users in real LDAP server."""
        client = shared_ldap_client

        await client.add_entry_universal(
            dn="ou=users,dc=flext,dc=local",
            attributes={"objectClass": ["organizationalUnit"], "ou": "users"},
        )

        await client.add_entry_universal(
            dn="cn=user1,ou=users,dc=flext,dc=local",
            attributes={
                "objectClass": ["inetOrgPerson"],
                "cn": "user1",
                "sn": "User1",
                "uid": "user1",
                "mail": "user1@internal.invalid",
            },
        )

        await client.add_entry_universal(
            dn="cn=user2,ou=users,dc=flext,dc=local",
            attributes={
                "objectClass": ["inetOrgPerson"],
                "cn": "user2",
                "sn": "User2",
                "uid": "user2",
                "mail": "user2@internal.invalid",
            },
        )

        repo = FlextLdapRepositories.UserRepository(client=client)

        result = await repo.search(
            base_dn="ou=users,dc=flext,dc=local",
            filter_str="(objectClass=inetOrgPerson)",
        )

        assert result.is_success, f"User search failed: {result.error}"
        assert len(result.value) >= 2

        await client.delete_entry_universal(dn="cn=user1,ou=users,dc=flext,dc=local")
        await client.delete_entry_universal(dn="cn=user2,ou=users,dc=flext,dc=local")
        await client.delete_entry_universal(dn="ou=users,dc=flext,dc=local")


@pytest.mark.integration
@pytest.mark.asyncio
class TestRealGroupRepository:
    """Test real group repository operations."""

    async def test_create_group_in_real_ldap(
        self, shared_ldap_client: FlextLdapClient
    ) -> None:
        """Test creating a group in real LDAP server."""
        client = shared_ldap_client

        await client.add_entry_universal(
            dn="ou=groups,dc=flext,dc=local",
            attributes={"objectClass": ["organizationalUnit"], "ou": "groups"},
        )

        repo = FlextLdapRepositories.GroupRepository(client=client)

        group = FlextLdapModels.Group(
            dn="cn=testgroup,ou=groups,dc=flext,dc=local",
            cn="testgroup",
            member=["cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local"],
            gid_number="1000",
            description="Test group for integration testing",
        )

        result = await repo.save(group)

        assert result.is_success, f"Group creation failed: {result.error}"

        await client.delete_entry_universal(
            dn="cn=testgroup,ou=groups,dc=flext,dc=local"
        )
        await client.delete_entry_universal(dn="ou=groups,dc=flext,dc=local")

    async def test_add_member_to_group_in_real_ldap(
        self, shared_ldap_client: FlextLdapClient
    ) -> None:
        """Test adding member to group in real LDAP server."""
        client = shared_ldap_client

        await client.add_entry_universal(
            dn="ou=groups,dc=flext,dc=local",
            attributes={"objectClass": ["organizationalUnit"], "ou": "groups"},
        )

        await client.add_entry_universal(
            dn="ou=users,dc=flext,dc=local",
            attributes={"objectClass": ["organizationalUnit"], "ou": "users"},
        )

        await client.add_entry_universal(
            dn="cn=member1,ou=users,dc=flext,dc=local",
            attributes={
                "objectClass": ["inetOrgPerson"],
                "cn": "member1",
                "sn": "Member1",
                "uid": "member1",
                "mail": "member1@internal.invalid",
            },
        )

        await client.add_entry_universal(
            dn="cn=membergroup,ou=groups,dc=flext,dc=local",
            attributes={
                "objectClass": ["groupOfNames"],
                "cn": "membergroup",
                "member": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
            },
        )

        repo = FlextLdapRepositories.GroupRepository(client=client)

        result = await repo.add_member_to_group(
            _group_dn="cn=membergroup,ou=groups,dc=flext,dc=local",
            _member_dn="cn=member1,ou=users,dc=flext,dc=local",
        )

        assert result.is_success, f"Add member failed: {result.error}"

        search_result = await client.search(
            base_dn="cn=membergroup,ou=groups,dc=flext,dc=local",
            filter_str="(objectClass=groupOfNames)",
            attributes=["member"],
        )

        assert search_result.is_success
        members = str(search_result.unwrap()[0].get("member", ""))
        assert "cn=member1,ou=users,dc=flext,dc=local" in members

        await client.delete_entry_universal(
            dn="cn=membergroup,ou=groups,dc=flext,dc=local"
        )
        await client.delete_entry_universal(dn="cn=member1,ou=users,dc=flext,dc=local")
        await client.delete_entry_universal(dn="ou=groups,dc=flext,dc=local")
        await client.delete_entry_universal(dn="ou=users,dc=flext,dc=local")

    async def test_remove_member_from_group_in_real_ldap(
        self, shared_ldap_client: FlextLdapClient
    ) -> None:
        """Test removing member from group in real LDAP server."""
        client = shared_ldap_client

        await client.add_entry_universal(
            dn="ou=groups,dc=flext,dc=local",
            attributes={"objectClass": ["organizationalUnit"], "ou": "groups"},
        )

        await client.add_entry_universal(
            dn="ou=users,dc=flext,dc=local",
            attributes={"objectClass": ["organizationalUnit"], "ou": "users"},
        )

        await client.add_entry_universal(
            dn="cn=removemember,ou=users,dc=flext,dc=local",
            attributes={
                "objectClass": ["inetOrgPerson"],
                "cn": "removemember",
                "sn": "RemoveMember",
                "uid": "removemember",
                "mail": "removemember@internal.invalid",
            },
        )

        await client.add_entry_universal(
            dn="cn=removegroup,ou=groups,dc=flext,dc=local",
            attributes={
                "objectClass": ["groupOfNames"],
                "cn": "removegroup",
                "member": [
                    "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
                    "cn=removemember,ou=users,dc=flext,dc=local",
                ],
            },
        )

        FlextLdapRepositories.GroupRepository(client=client)

        result = await client.remove_member(
            group_dn="cn=removegroup,ou=groups,dc=flext,dc=local",
            member_dn="cn=removemember,ou=users,dc=flext,dc=local",
        )

        assert result.is_success, f"Remove member failed: {result.error}"

        search_result = await client.search(
            base_dn="cn=removegroup,ou=groups,dc=flext,dc=local",
            filter_str="(objectClass=groupOfNames)",
            attributes=["member"],
        )

        assert search_result.is_success
        members = str(search_result.unwrap()[0].get("member", ""))
        assert "cn=removemember,ou=users,dc=flext,dc=local" not in members

        await client.delete_entry_universal(
            dn="cn=removegroup,ou=groups,dc=flext,dc=local"
        )
        await client.delete_entry_universal(
            dn="cn=removemember,ou=users,dc=flext,dc=local"
        )
        await client.delete_entry_universal(dn="ou=groups,dc=flext,dc=local")
        await client.delete_entry_universal(dn="ou=users,dc=flext,dc=local")

    async def test_get_group_members_from_real_ldap(
        self, shared_ldap_client: FlextLdapClient
    ) -> None:
        """Test retrieving group members from real LDAP server."""
        client = shared_ldap_client

        await client.add_entry_universal(
            dn="ou=groups,dc=flext,dc=local",
            attributes={"objectClass": ["organizationalUnit"], "ou": "groups"},
        )

        await client.add_entry_universal(
            dn="cn=membersgroup,ou=groups,dc=flext,dc=local",
            attributes={
                "objectClass": ["groupOfNames"],
                "cn": "membersgroup",
                "member": [
                    "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local",
                    "cn=member1,ou=users,dc=flext,dc=local",
                    "cn=member2,ou=users,dc=flext,dc=local",
                ],
            },
        )

        repo = FlextLdapRepositories.GroupRepository(client=client)

        result = await repo.get_group_members(
            "cn=membersgroup,ou=groups,dc=flext,dc=local"
        )

        assert result.is_success, f"Get members failed: {result.error}"
        assert len(result.value) >= 1
        assert "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local" in result.value

        await client.delete_entry_universal(
            dn="cn=membersgroup,ou=groups,dc=flext,dc=local"
        )
        await client.delete_entry_universal(dn="ou=groups,dc=flext,dc=local")

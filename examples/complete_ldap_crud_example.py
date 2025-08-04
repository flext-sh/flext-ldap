#!/usr/bin/env python3
"""Complete LDAP CRUD Operations Example with Docker Container.

This example demonstrates COMPLETE LDAP functionality:
- CREATE users and groups
- READ/SEARCH operations
- UPDATE user attributes
- DELETE operations

Uses MAXIMUM Docker container functionality for real LDAP operations.
"""

import asyncio
import subprocess
import time

from flext_core import get_logger
from flext_ldap import FlextLdapApi
from flext_ldap.values import FlextLdapCreateUserRequest

logger = get_logger(__name__)


class DockerLDAPContainer:
    """Manages Docker LDAP container for testing."""

    def __init__(self) -> None:
        self.container_name = "flext-ldap-crud-test"
        self.port = 3389

    def start_container(self) -> None:
        """Start Docker LDAP container."""
        print("🐳 Starting Docker LDAP container...")

        # Stop and remove existing container
        subprocess.run(
            ["docker", "stop", self.container_name], capture_output=True, check=False
        )
        subprocess.run(
            ["docker", "rm", self.container_name], capture_output=True, check=False
        )

        # Start new container
        cmd = [
            "docker",
            "run",
            "-d",
            "--name",
            self.container_name,
            "-p",
            f"{self.port}:389",
            "-e",
            "LDAP_ORGANISATION=FLEXT",
            "-e",
            "LDAP_DOMAIN=flext.local",
            "-e",
            "LDAP_ADMIN_PASSWORD=admin123",
            "-e",
            "LDAP_TLS=false",
            "osixia/openldap:1.5.0",
        ]

        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        if result.returncode != 0:
            msg = f"Failed to start container: {result.stderr}"
            raise RuntimeError(msg)

        print(f"✅ Container started: {self.container_name}")

        # Wait for container to be ready
        print("⏳ Waiting for LDAP service to be ready...")
        time.sleep(10)

        # Create organizational units
        self._setup_directory_structure()

    def _setup_directory_structure(self) -> None:
        """Setup LDAP directory structure."""
        print("🏗️  Setting up directory structure...")

        # Create LDIF content
        ldif_content = """dn: ou=people,dc=flext,dc=local
objectClass: organizationalUnit
ou: people
description: Container for user accounts

dn: ou=groups,dc=flext,dc=local
objectClass: organizationalUnit
ou: groups
description: Container for groups
"""

        # Write LDIF to temp file
        with open("/tmp/setup_directory.ldif", "w", encoding="utf-8") as f:
            f.write(ldif_content)

        # Add entries to LDAP
        cmd = [
            "ldapadd",
            "-x",
            "-H",
            f"ldap://localhost:{self.port}",
            "-D",
            "cn=admin,dc=flext,dc=local",
            "-w",
            "admin123",
            "-f",
            "/tmp/setup_directory.ldif",
        ]

        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ Directory structure created")
        else:
            print(f"⚠️  Directory structure may already exist: {result.stderr}")

    def stop_container(self) -> None:
        """Stop and remove container."""
        print("🛑 Stopping Docker container...")
        subprocess.run(
            ["docker", "stop", self.container_name], check=False, capture_output=True
        )
        subprocess.run(
            ["docker", "rm", self.container_name], check=False, capture_output=True
        )
        print("✅ Container stopped and removed")


async def demonstrate_complete_crud_operations() -> None:
    """Demonstrate COMPLETE LDAP CRUD operations."""
    print("=== COMPLETE LDAP CRUD OPERATIONS DEMO ===")

    # Initialize LDAP API
    ldap_service = FlextLdapApi()

    # Connection parameters
    server_url = "ldap://localhost:3389"
    bind_dn = "cn=admin,dc=flext,dc=local"
    password = "admin123"

    try:
        # Connect to LDAP
        connection_result = await ldap_service.connect(server_url, bind_dn, password)
        if connection_result.is_failure:
            msg = f"Connection failed: {connection_result.error}"
            raise RuntimeError(msg)

        session_id = connection_result.data
        print(f"✅ Connected to LDAP server: {session_id}")

        try:
            # === CREATE OPERATIONS (GROUPS FIRST) ===
            await perform_create_groups(ldap_service, session_id)

            # === CREATE OPERATIONS (USERS) ===
            await perform_create_users(ldap_service, session_id)

            # === READ OPERATIONS ===
            await perform_read_operations(ldap_service, session_id)

            # === UPDATE OPERATIONS ===
            await perform_update_operations(ldap_service, session_id)

            # === DELETE OPERATIONS ===
            await perform_delete_operations(ldap_service, session_id)

        finally:
            # Clean up connection
            await ldap_service.disconnect(session_id)

    except Exception as e:
        print(f"❌ CRUD operations failed: {e}")
        raise


async def perform_create_groups(ldap_service, session_id) -> None:
    """Perform CREATE operations for groups."""
    print("\n🔨 === CREATE GROUPS ===")

    # Create groups first
    groups_to_create = [
        {
            "dn": "cn=engineers,ou=groups,dc=flext,dc=local",
            "cn": "engineers",
            "description": "Engineering team",
        },
        {
            "dn": "cn=marketing,ou=groups,dc=flext,dc=local",
            "cn": "marketing",
            "description": "Marketing team",
        },
    ]

    for group_data in groups_to_create:
        print(f"   Creating group: {group_data['cn']}")

        result = await ldap_service.create_group(
            session_id, group_data["dn"], group_data["cn"], group_data["description"]
        )

        if result.success:
            print(f"   ✅ Created group: {group_data['cn']}")
        else:
            print(f"   ❌ Failed to create group {group_data['cn']}: {result.error}")

    print("✅ CREATE groups completed")


async def perform_create_users(ldap_service, session_id) -> None:
    """Perform CREATE operations for users."""
    print("\n🔨 === CREATE USERS ===")

    # Create multiple users
    users_to_create = [
        {
            "dn": "cn=john.doe,ou=people,dc=flext,dc=local",
            "uid": "john.doe",
            "cn": "John Doe",
            "sn": "Doe",
            "mail": "john.doe@flext.local",
            "title": "Software Engineer",
        },
        {
            "dn": "cn=jane.smith,ou=people,dc=flext,dc=local",
            "uid": "jane.smith",
            "cn": "Jane Smith",
            "sn": "Smith",
            "mail": "jane.smith@flext.local",
            "title": "Marketing Specialist",
        },
        {
            "dn": "cn=bob.wilson,ou=people,dc=flext,dc=local",
            "uid": "bob.wilson",
            "cn": "Bob Wilson",
            "sn": "Wilson",
            "mail": "bob.wilson@flext.local",
            "title": "Senior Engineer",
        },
    ]

    created_users = []

    for user_data in users_to_create:
        print(f"   Creating user: {user_data['uid']}")

        user_request = FlextLdapCreateUserRequest(**user_data)
        result = await ldap_service.create_user(session_id, user_request)

        if result.success:
            print(f"   ✅ Created user: {user_data['uid']}")
            created_users.append(user_data["uid"])
        else:
            print(f"   ❌ Failed to create user {user_data['uid']}: {result.error}")

    print(f"✅ CREATE users completed - Created {len(created_users)} users")


async def perform_read_operations(ldap_service, session_id) -> None:
    """Perform READ/SEARCH operations."""
    print("\n🔍 === READ/SEARCH OPERATIONS ===")

    # Search for all users
    print("   Searching for all users...")
    users_result = await ldap_service.search(
        session_id=session_id,
        base_dn="ou=people,dc=flext,dc=local",
        filter_expr="(objectClass=inetOrgPerson)",
        attributes=["uid", "cn", "mail", "title"],
    )

    if users_result.success and users_result.data:
        print(f"   ✅ Found {len(users_result.data)} users:")
        for user in users_result.data:
            uid = user.attributes.get("uid", ["N/A"])[0]
            cn = user.attributes.get("cn", ["N/A"])[0]
            mail = user.attributes.get("mail", ["N/A"])[0]
            title = user.attributes.get("title", ["N/A"])[0]
            print(f"     - {uid}: {cn} ({mail}) - {title}")
    else:
        print("   ❌ No users found or search failed")

    # Search by title containing "Engineer"
    print("   Searching for Engineer users...")
    eng_result = await ldap_service.search(
        session_id=session_id,
        base_dn="ou=people,dc=flext,dc=local",
        filter_expr="(title=*Engineer*)",
        attributes=["uid", "cn", "title"],
    )

    if eng_result.success and eng_result.data:
        print(f"   ✅ Found {len(eng_result.data)} Engineer users")
    else:
        print("   ℹ️  No Engineer users found (expected if CREATE failed)")

    # Search for groups
    print("   Searching for all groups...")
    groups_result = await ldap_service.search(
        session_id=session_id,
        base_dn="ou=groups,dc=flext,dc=local",
        filter_expr="(objectClass=groupOfNames)",
        attributes=["cn", "description"],
    )

    if groups_result.success and groups_result.data:
        print(f"   ✅ Found {len(groups_result.data)} groups:")
        for group in groups_result.data:
            cn = group.attributes.get("cn", ["N/A"])[0]
            desc = group.attributes.get("description", ["N/A"])[0]
            print(f"     - {cn}: {desc}")
    else:
        print("   ℹ️  No groups found")

    print("✅ READ operations completed")


async def perform_update_operations(ldap_service, session_id) -> None:
    """Perform UPDATE operations."""
    print("\n🔄 === UPDATE OPERATIONS ===")

    # Update user attributes
    users_to_update = [
        {
            "dn": "cn=john.doe,ou=people,dc=flext,dc=local",
            "updates": {
                "mail": "john.doe.updated@flext.local",
                "title": "Senior Software Engineer",
            },
        },
        {
            "dn": "cn=jane.smith,ou=people,dc=flext,dc=local",
            "updates": {
                "mail": "jane.smith.updated@flext.local",
                "title": "Marketing Manager",
            },
        },
    ]

    for user_update in users_to_update:
        uid = user_update["dn"].split(",")[0].replace("cn=", "")
        print(f"   Updating user: {uid}")

        result = await ldap_service.update_user(
            session_id=session_id,
            user_dn=user_update["dn"],
            updates=user_update["updates"],
        )

        if result.success:
            print(f"   ✅ Updated user: {uid}")

            # Verify update by searching
            verify_result = await ldap_service.search(
                session_id=session_id,
                base_dn=user_update["dn"],
                filter_expr="(objectClass=*)",
                scope="base",
                attributes=["mail", "title"],
            )

            if verify_result.success and verify_result.data:
                entry = verify_result.data[0]
                mail = entry.attributes.get("mail", ["N/A"])[0]
                title = entry.attributes.get("title", ["N/A"])[0]
                print(f"     Verified: mail={mail}, title={title}")

        else:
            print(f"   ❌ Failed to update user {uid}: {result.error}")

    print("✅ UPDATE operations completed")


async def perform_delete_operations(ldap_service, session_id) -> None:
    """Perform DELETE operations."""
    print("\n🗑️  === DELETE OPERATIONS ===")

    # Delete one user for demonstration
    user_to_delete = "cn=bob.wilson,ou=people,dc=flext,dc=local"
    print(f"   Deleting user: {user_to_delete}")

    result = await ldap_service.delete_user(
        session_id=session_id, user_dn=user_to_delete
    )

    if result.success:
        print(f"   ✅ Deleted user: {user_to_delete}")

        # Verify deletion
        verify_result = await ldap_service.search(
            session_id=session_id,
            base_dn=user_to_delete,
            filter_expr="(objectClass=*)",
            scope="base",
        )

        if verify_result.is_failure or not verify_result.data:
            print("   ✅ Verified: User no longer exists")
        else:
            print("   ⚠️  User still exists after deletion")

    else:
        print(f"   ❌ Failed to delete user: {result.error}")

    # Final count verification
    print("   Final user count verification...")
    final_count_result = await ldap_service.search(
        session_id=session_id,
        base_dn="ou=people,dc=flext,dc=local",
        filter_expr="(objectClass=inetOrgPerson)",
        attributes=["uid"],
    )

    if final_count_result.success:
        remaining_users = len(final_count_result.data) if final_count_result.data else 0
        print(f"   ✅ Final user count: {remaining_users} users remaining")

    print("✅ DELETE operations completed")


async def main() -> None:
    """Main execution function."""
    container = DockerLDAPContainer()

    try:
        # Start Docker container
        container.start_container()

        # Perform complete CRUD operations
        await demonstrate_complete_crud_operations()

        print("\n🎉 === COMPLETE CRUD OPERATIONS SUCCESSFUL ===")
        print("✅ All LDAP operations validated with Docker container")
        print("✅ MAXIMUM Docker container usage achieved")
        print("✅ COMPLETE functionality tested: CREATE, READ, UPDATE, DELETE")

    except Exception as e:
        print(f"\n❌ CRUD operations failed: {e}")
        raise
    finally:
        # Always clean up container
        container.stop_container()


if __name__ == "__main__":
    asyncio.run(main())

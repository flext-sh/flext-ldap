"""LDAP test data management and loading utilities.

Provides comprehensive test data management for flext-ldap integration tests,
including creation, cleanup, and verification of test data in real LDAP servers.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Any

from flext_core import FlextLogger, FlextResult
from ldap3 import Connection

logger = FlextLogger(__name__)


class LdapTestDataLoader:
    """Manages test data lifecycle in LDAP servers for integration tests.

    Provides methods to:
    - Load standard test data (users, groups, OUs) into LDAP
    - Clean up test data after tests
    - Verify test data exists and is correct
    - Create and manage temporary test entries

    Supports real LDAP operations against actual LDAP servers.
    """

    # Standard test organization unit
    OU_PEOPLE_DN = "ou=people,dc=flext,dc=local"
    OU_GROUPS_DN = "ou=groups,dc=flext,dc=local"
    OU_SYSTEM_DN = "ou=system,dc=flext,dc=local"

    # Standard test user DNs
    TEST_USER_DN = "uid=testuser,ou=people,dc=flext,dc=local"
    TEST_USER2_DN = "uid=testuser2,ou=people,dc=flext,dc=local"
    TEST_USER3_DN = "uid=testuser3,ou=people,dc=flext,dc=local"

    # Standard test group DNs
    TEST_GROUP_DN = "cn=testgroup,ou=groups,dc=flext,dc=local"
    TEST_GROUP2_DN = "cn=testgroup2,ou=groups,dc=flext,dc=local"
    TEST_ADMIN_DN = "cn=testadmin,ou=system,dc=flext,dc=local"

    def __init__(self, connection: Connection) -> None:
        """Initialize test data loader with LDAP connection.

        Args:
            connection: Connected ldap3.Connection instance

        """
        self.connection = connection

    def load_all_test_data(self) -> FlextResult[None]:
        """Load all standard test data into LDAP.

        Creates:
        - Organizational Units (people, groups, system)
        - Test users (testuser, testuser2, testuser3)
        - Test groups (testgroup, testgroup2)
        - System entries (testadmin)

        Returns:
            FlextResult[None]: Success or failure with error message

        """
        try:
            # Create organizational units
            ou_result = self._create_organizational_units()
            if ou_result.is_failure:
                return ou_result

            # Create test users
            users_result = self._create_test_users()
            if users_result.is_failure:
                return users_result

            # Create test groups
            groups_result = self._create_test_groups()
            if groups_result.is_failure:
                return groups_result

            # Create system entries
            system_result = self._create_system_entries()
            if system_result.is_failure:
                return system_result

            logger.info("All test data loaded successfully")
            return FlextResult[None].ok(None)

        except Exception as e:
            error_msg = f"Failed to load test data: {e!s}"
            logger.exception(error_msg)
            return FlextResult[None].fail(error_msg)

    def _create_organizational_units(self) -> FlextResult[None]:
        """Create organizational unit structure for tests."""
        try:
            # Create people OU
            self.connection.add(
                self.OU_PEOPLE_DN,
                object_class=["top", "organizationalUnit"],
                attributes={
                    "ou": "people",
                    "description": "People organizational unit",
                },
            )

            if self.connection.result["description"] != "success":
                # OU might already exist, which is fine
                logger.debug(
                    f"OU {self.OU_PEOPLE_DN} creation: {self.connection.result}"
                )

            # Create groups OU
            self.connection.add(
                self.OU_GROUPS_DN,
                object_class=["top", "organizationalUnit"],
                attributes={
                    "ou": "groups",
                    "description": "Groups organizational unit",
                },
            )

            if self.connection.result["description"] != "success":
                logger.debug(
                    f"OU {self.OU_GROUPS_DN} creation: {self.connection.result}"
                )

            # Create system OU
            self.connection.add(
                self.OU_SYSTEM_DN,
                object_class=["top", "organizationalUnit"],
                attributes={
                    "ou": "system",
                    "description": "System organizational unit",
                },
            )

            if self.connection.result["description"] != "success":
                logger.debug(
                    f"OU {self.OU_SYSTEM_DN} creation: {self.connection.result}"
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            error_msg = f"Failed to create organizational units: {e!s}"
            logger.exception(error_msg)
            return FlextResult[None].fail(error_msg)

    def _create_test_users(self) -> FlextResult[None]:
        """Create test users for authentication and search tests."""
        try:
            # Create testuser
            self.connection.add(
                self.TEST_USER_DN,
                object_class=["top", "inetOrgPerson"],
                attributes={
                    "uid": "testuser",
                    "cn": "Test User",
                    "sn": "User",
                    "givenName": "Test",
                    "mail": "testuser@flext.local",
                    "telephoneNumber": "+1234567890",
                    "userPassword": "test123",
                },
            )
            logger.debug(f"testuser creation: {self.connection.result}")

            # Create testuser2
            self.connection.add(
                self.TEST_USER2_DN,
                object_class=["top", "inetOrgPerson"],
                attributes={
                    "uid": "testuser2",
                    "cn": "Test User 2",
                    "sn": "User",
                    "givenName": "Test",
                    "mail": "testuser2@flext.local",
                    "userPassword": "test456",
                },
            )
            logger.debug(f"testuser2 creation: {self.connection.result}")

            # Create testuser3
            self.connection.add(
                self.TEST_USER3_DN,
                object_class=["top", "inetOrgPerson"],
                attributes={
                    "uid": "testuser3",
                    "cn": "Test User 3",
                    "sn": "User",
                    "givenName": "Test",
                    "mail": "testuser3@flext.local",
                    "userPassword": "test789",
                },
            )
            logger.debug(f"testuser3 creation: {self.connection.result}")

            return FlextResult[None].ok(None)

        except Exception as e:
            error_msg = f"Failed to create test users: {e!s}"
            logger.exception(error_msg)
            return FlextResult[None].fail(error_msg)

    def _create_test_groups(self) -> FlextResult[None]:
        """Create test groups for membership and search tests."""
        try:
            # Create testgroup
            self.connection.add(
                self.TEST_GROUP_DN,
                object_class=["top", "groupOfNames"],
                attributes={
                    "cn": "testgroup",
                    "description": "Test group for membership testing",
                    "member": self.TEST_USER_DN,
                },
            )
            logger.debug(f"testgroup creation: {self.connection.result}")

            # Create testgroup2
            self.connection.add(
                self.TEST_GROUP2_DN,
                object_class=["top", "groupOfNames"],
                attributes={
                    "cn": "testgroup2",
                    "description": "Second test group",
                    "member": [self.TEST_USER_DN, self.TEST_USER2_DN],
                },
            )
            logger.debug(f"testgroup2 creation: {self.connection.result}")

            return FlextResult[None].ok(None)

        except Exception as e:
            error_msg = f"Failed to create test groups: {e!s}"
            logger.exception(error_msg)
            return FlextResult[None].fail(error_msg)

    def _create_system_entries(self) -> FlextResult[None]:
        """Create system test entries."""
        try:
            # Create system test admin entry
            self.connection.add(
                self.TEST_ADMIN_DN,
                object_class=["top", "inetOrgPerson"],
                attributes={
                    "cn": "testadmin",
                    "sn": "Admin",
                    "givenName": "Test",
                    "mail": "admin@flext.local",
                    "userPassword": "admin123",
                },
            )
            logger.debug(f"testadmin creation: {self.connection.result}")

            return FlextResult[None].ok(None)

        except Exception as e:
            error_msg = f"Failed to create system entries: {e!s}"
            logger.exception(error_msg)
            return FlextResult[None].fail(error_msg)

    def cleanup_all_test_data(self) -> FlextResult[None]:
        """Clean up all test data created by this loader.

        Removes:
        - All test entries (users, groups, OUs)
        - System entries
        - Temporary test data

        Returns:
            FlextResult[None]: Success or failure with error message

        """
        try:
            # Delete in order: users first, then groups, then OUs
            entries_to_delete = [
                self.TEST_ADMIN_DN,
                self.TEST_USER_DN,
                self.TEST_USER2_DN,
                self.TEST_USER3_DN,
                self.TEST_GROUP_DN,
                self.TEST_GROUP2_DN,
                self.OU_SYSTEM_DN,
                self.OU_GROUPS_DN,
                self.OU_PEOPLE_DN,
            ]

            for dn in entries_to_delete:
                try:
                    self.connection.delete(dn)
                    logger.debug(f"Deleted {dn}: {self.connection.result}")
                except Exception as e:
                    # Entry might not exist, continue
                    logger.debug(f"Failed to delete {dn}: {e!s}")

            logger.info("Test data cleanup completed")
            return FlextResult[None].ok(None)

        except Exception as e:
            error_msg = f"Failed to cleanup test data: {e!s}"
            logger.exception(error_msg)
            return FlextResult[None].fail(error_msg)

    def verify_test_data_exists(self) -> FlextResult[dict[str, bool]]:
        """Verify that all expected test data exists in LDAP.

        Returns:
            FlextResult[dict]: Dictionary of entry_name -> exists (bool)

        """
        try:
            results: dict[str, bool] = {}

            entries_to_check = {
                "testuser": self.TEST_USER_DN,
                "testuser2": self.TEST_USER2_DN,
                "testuser3": self.TEST_USER3_DN,
                "testgroup": self.TEST_GROUP_DN,
                "testgroup2": self.TEST_GROUP2_DN,
                "testadmin": self.TEST_ADMIN_DN,
                "ou_people": self.OU_PEOPLE_DN,
                "ou_groups": self.OU_GROUPS_DN,
                "ou_system": self.OU_SYSTEM_DN,
            }

            for name, dn in entries_to_check.items():
                self.connection.search(
                    dn,
                    "(objectClass=*)",
                    search_scope="BASE",
                )
                results[name] = len(self.connection.entries) > 0

            return FlextResult[dict[str, bool]].ok(results)

        except Exception as e:
            error_msg = f"Failed to verify test data: {e!s}"
            logger.exception(error_msg)
            return FlextResult[dict[str, bool]].fail(error_msg)

    def create_temporary_entry(
        self, dn: str, object_classes: list[str], attributes: dict[str, Any]
    ) -> FlextResult[None]:
        """Create a temporary test entry.

        Args:
            dn: Distinguished name of entry to create
            object_classes: List of object classes
            attributes: Dictionary of attributes

        Returns:
            FlextResult[None]: Success or failure

        """
        try:
            self.connection.add(
                dn,
                object_class=object_classes,
                attributes=attributes,
            )

            if self.connection.result["description"] != "success":
                return FlextResult[None].fail(
                    f"Failed to create entry: {self.connection.result['message']}"
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            return FlextResult[None].fail(f"Failed to create entry: {e!s}")

    def delete_temporary_entry(self, dn: str) -> FlextResult[None]:
        """Delete a temporary test entry.

        Args:
            dn: Distinguished name of entry to delete

        Returns:
            FlextResult[None]: Success or failure

        """
        try:
            self.connection.delete(dn)

            if self.connection.result["description"] != "success":
                return FlextResult[None].fail(
                    f"Failed to delete entry: {self.connection.result['message']}"
                )

            return FlextResult[None].ok(None)

        except Exception as e:
            return FlextResult[None].fail(f"Failed to delete entry: {e!s}")


__all__ = ["LdapTestDataLoader"]

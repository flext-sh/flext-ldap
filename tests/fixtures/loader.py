"""Fixture data loader for flext-ldap tests.

Loads test data from JSON and LDIF files in fixtures directory.
Reuses TestFixtures from __init__.py and adds LDAP-specific conversions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextLogger
from flext_ldif import FlextLdif

from tests.fixtures import TestFixtures

logger = FlextLogger(__name__)


class LdapTestFixtures:
    """Loader for LDAP test fixtures.

    Extends TestFixtures with LDAP-specific methods.
    """

    @staticmethod
    def load_users_json() -> list[dict[str, object]]:
        """Load test users from JSON file."""
        result = TestFixtures.load_json("test_users.json")
        if result.is_success:
            return result.unwrap()
        logger.warning(f"Failed to load users: {result.error}")
        return []

    @staticmethod
    def load_groups_json() -> list[dict[str, object]]:
        """Load test groups from JSON file."""
        result = TestFixtures.load_json("test_groups.json")
        if result.is_success:
            return result.unwrap()
        logger.warning(f"Failed to load groups: {result.error}")
        return []

    @staticmethod
    def load_base_ldif() -> str:
        """Load base LDIF structure from file."""
        result = TestFixtures.load_ldif("test_base.ldif")
        if result.is_success:
            return result.unwrap()
        logger.warning(f"Failed to load base LDIF: {result.error}")
        return ""

    @staticmethod
    def load_base_ldif_entries() -> list[object]:  # type: ignore[type-arg]
        """Load and parse base LDIF structure to Entry models."""
        ldif_content = LdapTestFixtures.load_base_ldif()
        if not ldif_content:
            return []

        # Use FlextLdif to parse LDIF (reusing flext-ldif)
        ldif = FlextLdif()
        result = ldif.parse(ldif_content)
        if result.is_success:
            entries = result.unwrap()
            return list(entries)
        logger.warning(f"Failed to parse base LDIF: {result.error}")
        return []

    @staticmethod
    def convert_user_json_to_entry(user_data: dict[str, object]) -> dict[str, object]:
        """Convert user JSON data to Entry-compatible format."""
        # Map JSON fields to LDAP attributes
        object_classes = user_data.get("object_classes", [])
        if not isinstance(object_classes, list):
            object_classes = []

        attributes: dict[str, list[str]] = {
            "objectClass": [str(oc) for oc in object_classes],
            "uid": [str(user_data.get("uid", ""))],
            "cn": [str(user_data.get("cn", ""))],
            "sn": [str(user_data.get("sn", ""))],
        }

        if "given_name" in user_data:
            attributes["givenName"] = [str(user_data["given_name"])]
        if "mail" in user_data:
            attributes["mail"] = [str(user_data["mail"])]
        if "telephone_number" in user_data:
            attributes["telephoneNumber"] = [str(user_data["telephone_number"])]
        if "mobile" in user_data:
            attributes["mobile"] = [str(user_data["mobile"])]
        if "department" in user_data:
            attributes["departmentNumber"] = [str(user_data["department"])]
        if "title" in user_data:
            attributes["title"] = [str(user_data["title"])]
        if "organization" in user_data:
            attributes["o"] = [str(user_data["organization"])]
        if "organizational_unit" in user_data:
            attributes["ou"] = [str(user_data["organizational_unit"])]

        return {
            "dn": str(user_data.get("dn", "")),
            "attributes": attributes,
        }

    @staticmethod
    def convert_group_json_to_entry(group_data: dict[str, object]) -> dict[str, object]:
        """Convert group JSON data to Entry-compatible format."""
        object_classes = group_data.get("object_classes", [])
        if not isinstance(object_classes, list):
            object_classes = []

        attributes: dict[str, list[str]] = {
            "objectClass": [str(oc) for oc in object_classes],
            "cn": [str(group_data.get("cn", ""))],
        }

        if "description" in group_data:
            attributes["description"] = [str(group_data["description"])]
        if "member_dns" in group_data:
            member_dns = group_data["member_dns"]
            if isinstance(member_dns, list):
                attributes["member"] = [str(m) for m in member_dns]
            else:
                attributes["member"] = [str(member_dns)]

        return {
            "dn": str(group_data.get("dn", "")),
            "attributes": attributes,
        }

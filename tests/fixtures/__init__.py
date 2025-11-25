"""Centralized test fixtures and data loaders for flext-ldap tests.

This module provides utilities to load test data from JSON and LDIF files
following FLEXT standards for centralized test infrastructure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import json
from pathlib import Path

from flext_core import FlextLogger, FlextResult
from flext_ldif import FlextLdif, FlextLdifConfig

from .constants import OID, OUD, RFC, General, OpenLDAP2, TestConstants

logger = FlextLogger(__name__)

FIXTURES_DIR = Path(__file__).parent


class TestFixtures:
    """Centralized test fixtures loader following FLEXT patterns."""

    @staticmethod
    def load_json(filename: str) -> FlextResult[list[dict[str, object]]]:
        """Load JSON test data from fixtures directory."""
        try:
            filepath = FIXTURES_DIR / filename
            if not filepath.exists():
                return FlextResult[list[dict[str, object]]].fail(
                    f"Fixture file not found: {filename}",
                )

            with Path(filepath).open(encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, list):
                return FlextResult[list[dict[str, object]]].fail(
                    f"Expected list in {filename}, got {type(data)}",
                )

            return FlextResult[list[dict[str, object]]].ok(data)
        except Exception as e:
            return FlextResult[list[dict[str, object]]].fail(
                f"Failed to load JSON fixture {filename}: {e}",
            )

    @staticmethod
    def load_ldif(filename: str) -> FlextResult[str]:
        """Load LDIF test data from fixtures directory."""
        try:
            filepath = FIXTURES_DIR / filename
            if not filepath.exists():
                return FlextResult[str].fail(f"Fixture file not found: {filename}")

            with Path(filepath).open(encoding="utf-8") as f:
                content = f.read()

            return FlextResult[str].ok(content)
        except Exception as e:
            return FlextResult[str].fail(f"Failed to load LDIF fixture {filename}: {e}")

    @staticmethod
    def load_docker_config() -> FlextResult[dict[str, object]]:
        """Load Docker configuration for test container."""
        try:
            filepath = FIXTURES_DIR / "docker_config.json"
            if not filepath.exists():
                return FlextResult[dict[str, object]].fail(
                    "Docker config file not found",
                )

            with Path(filepath).open(encoding="utf-8") as f:
                config = json.load(f)

            return FlextResult[dict[str, object]].ok(config)
        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Failed to load Docker config: {e}",
            )

    @classmethod
    def get_test_users(cls) -> FlextResult[list[dict[str, object]]]:
        """Get test users list (convenience method).

        Returns:
            FlextResult containing test users list or error (no fallback)

        """
        return cls.load_json("test_users.json")

    @classmethod
    def get_test_groups(cls) -> FlextResult[list[dict[str, object]]]:
        """Get test groups list (convenience method).

        Returns:
            FlextResult containing test groups list or error (no fallback)

        """
        return cls.load_json("test_groups.json")

    @classmethod
    def get_base_ldif(cls) -> FlextResult[str]:
        """Get base LDIF content (convenience method).

        Returns:
            FlextResult containing LDIF content or error (no fallback)

        """
        return cls.load_ldif("test_base.ldif")

    @classmethod
    def get_docker_config(cls) -> FlextResult[dict[str, object]]:
        """Get Docker configuration (convenience method).

        Returns:
            FlextResult containing Docker config or error (no fallback)

        """
        return cls.load_docker_config()


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
    def load_base_ldif_entries() -> list[object]:
        """Load and parse base LDIF structure to Entry models."""
        ldif_content = LdapTestFixtures.load_base_ldif()
        if not ldif_content:
            return []

        # Use FlextLdif to parse LDIF (reusing flext-ldif)
        # Use RFC server type for test fixtures (generic parsing without quirks)
        config = FlextLdifConfig.model_validate({"quirks_server_type": "rfc"})
        ldif = FlextLdif(config=config)
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


__all__ = [
    "FIXTURES_DIR",
    "OID",
    "OUD",
    "RFC",
    "General",
    "LdapTestFixtures",
    "OpenLDAP2",
    "TestConstants",
    "TestFixtures",
]

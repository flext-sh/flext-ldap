"""Centralized test fixtures and data loaders for flext-ldap tests.

This module provides utilities to load test data from JSON and LDIF files
following FLEXT standards for centralized test infrastructure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import json
from pathlib import Path

from flext_core import FlextLogger, FlextResult, FlextTypes

logger = FlextLogger(__name__)

FIXTURES_DIR = Path(__file__).parent


class TestFixtures:
    """Centralized test fixtures loader following FLEXT patterns."""

    @staticmethod
    def load_json(filename: str) -> FlextResult[list[FlextTypes.Dict]]:
        """Load JSON test data from fixtures directory."""
        try:
            filepath = FIXTURES_DIR / filename
            if not filepath.exists():
                return FlextResult[list[FlextTypes.Dict]].fail(
                    f"Fixture file not found: {filename}"
                )

            with open(filepath) as f:
                data = json.load(f)

            if not isinstance(data, list):
                return FlextResult[list[FlextTypes.Dict]].fail(
                    f"Expected list in {filename}, got {type(data)}"
                )

            return FlextResult[list[FlextTypes.Dict]].ok(data)
        except Exception as e:
            return FlextResult[list[FlextTypes.Dict]].fail(
                f"Failed to load JSON fixture {filename}: {e}"
            )

    @staticmethod
    def load_ldif(filename: str) -> FlextResult[str]:
        """Load LDIF test data from fixtures directory."""
        try:
            filepath = FIXTURES_DIR / filename
            if not filepath.exists():
                return FlextResult[str].fail(f"Fixture file not found: {filename}")

            with open(filepath) as f:
                content = f.read()

            return FlextResult[str].ok(content)
        except Exception as e:
            return FlextResult[str].fail(f"Failed to load LDIF fixture {filename}: {e}")

    @staticmethod
    def load_docker_config() -> FlextResult[FlextTypes.Dict]:
        """Load Docker configuration for test container."""
        try:
            filepath = FIXTURES_DIR / "docker_config.json"
            if not filepath.exists():
                return FlextResult[FlextTypes.Dict].fail("Docker config file not found")

            with open(filepath) as f:
                config = json.load(f)

            return FlextResult[FlextTypes.Dict].ok(config)
        except Exception as e:
            return FlextResult[FlextTypes.Dict].fail(
                f"Failed to load Docker config: {e}"
            )

    @classmethod
    def get_test_users(cls) -> list[FlextTypes.Dict]:
        """Get test users list (convenience method)."""
        result = cls.load_json("test_users.json")
        return result.value if result.is_success else []

    @classmethod
    def get_test_groups(cls) -> list[FlextTypes.Dict]:
        """Get test groups list (convenience method)."""
        result = cls.load_json("test_groups.json")
        return result.value if result.is_success else []

    @classmethod
    def get_base_ldif(cls) -> str:
        """Get base LDIF content (convenience method)."""
        result = cls.load_ldif("test_base.ldif")
        return result.value if result.is_success else ""

    @classmethod
    def get_docker_config(cls) -> FlextTypes.Dict:
        """Get Docker configuration (convenience method)."""
        result = cls.load_docker_config()
        return result.value if result.is_success else {}


__all__ = ["TestFixtures", "FIXTURES_DIR"]

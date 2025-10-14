"""Centralized test fixtures and data loaders for flext-ldap tests.

This module provides utilities to load test data from JSON and LDIF files
following FLEXT standards for centralized test infrastructure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import json
from pathlib import Path

from flext_core import FlextCore

logger = FlextCore.Logger(__name__)

FIXTURES_DIR = Path(__file__).parent


class TestFixtures:
    """Centralized test fixtures loader following FLEXT patterns."""

    @staticmethod
    def load_json(filename: str) -> FlextCore.Result[list[FlextCore.Types.Dict]]:
        """Load JSON test data from fixtures directory."""
        try:
            filepath = FIXTURES_DIR / filename
            if not filepath.exists():
                return FlextCore.Result[list[FlextCore.Types.Dict]].fail(
                    f"Fixture file not found: {filename}"
                )

            with Path(filepath).open(encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, list):
                return FlextCore.Result[list[FlextCore.Types.Dict]].fail(
                    f"Expected list in {filename}, got {type(data)}"
                )

            return FlextCore.Result[list[FlextCore.Types.Dict]].ok(data)
        except Exception as e:
            return FlextCore.Result[list[FlextCore.Types.Dict]].fail(
                f"Failed to load JSON fixture {filename}: {e}"
            )

    @staticmethod
    def load_ldif(filename: str) -> FlextCore.Result[str]:
        """Load LDIF test data from fixtures directory."""
        try:
            filepath = FIXTURES_DIR / filename
            if not filepath.exists():
                return FlextCore.Result[str].fail(f"Fixture file not found: {filename}")

            with Path(filepath).open(encoding="utf-8") as f:
                content = f.read()

            return FlextCore.Result[str].ok(content)
        except Exception as e:
            return FlextCore.Result[str].fail(
                f"Failed to load LDIF fixture {filename}: {e}"
            )

    @staticmethod
    def load_docker_config() -> FlextCore.Result[FlextCore.Types.Dict]:
        """Load Docker configuration for test container."""
        try:
            filepath = FIXTURES_DIR / "docker_config.json"
            if not filepath.exists():
                return FlextCore.Result[FlextCore.Types.Dict].fail(
                    "Docker config file not found"
                )

            with Path(filepath).open(encoding="utf-8") as f:
                config = json.load(f)

            return FlextCore.Result[FlextCore.Types.Dict].ok(config)
        except Exception as e:
            return FlextCore.Result[FlextCore.Types.Dict].fail(
                f"Failed to load Docker config: {e}"
            )

    @classmethod
    def get_test_users(cls) -> list[FlextCore.Types.Dict]:
        """Get test users list (convenience method)."""
        result = cls.load_json("test_users.json")
        return result.value if result.is_success else []

    @classmethod
    def get_test_groups(cls) -> list[FlextCore.Types.Dict]:
        """Get test groups list (convenience method)."""
        result = cls.load_json("test_groups.json")
        return result.value if result.is_success else []

    @classmethod
    def get_base_ldif(cls) -> str:
        """Get base LDIF content (convenience method)."""
        result = cls.load_ldif("test_base.ldif")
        return result.value if result.is_success else ""

    @classmethod
    def get_docker_config(cls) -> FlextCore.Types.Dict:
        """Get Docker configuration (convenience method)."""
        result = cls.load_docker_config()
        return result.value if result.is_success else {}


__all__ = ["FIXTURES_DIR", "TestFixtures"]

"""Unit tests for version and package metadata.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit


class TestVersion:
    """Tests for version and package metadata."""

    def test_version_is_string(self) -> None:
        """Test that __version__ is a string."""
        # Import directly from module
        from flext_ldap.__version__ import __version__ as version_str

        assert isinstance(version_str, str)
        assert len(version_str) > 0

    def test_version_format(self) -> None:
        """Test that version follows semantic versioning format."""
        from flext_ldap.__version__ import __version__ as version_str

        # Version should be in format X.Y.Z or similar
        parts = version_str.split(".")
        assert len(parts) >= 2, (
            f"Version {version_str} should have at least major.minor"
        )
        # All parts should be numeric or contain valid version identifiers
        for part in parts:
            assert len(part) > 0, "Version part cannot be empty"

    def test_version_info_exists(self) -> None:
        """Test that version_info can be imported."""
        from flext_ldap.__version__ import __version_info__

        assert __version_info__ is not None
        assert isinstance(__version_info__, tuple)
        assert len(__version_info__) >= 2

    def test_version_metadata_imports(self) -> None:
        """Test that all version metadata can be imported."""
        from flext_ldap.__version__ import (
            __author__,
            __author_email__,
            __description__,
            __license__,
            __title__,
            __url__,
        )

        assert isinstance(__title__, str)
        assert isinstance(__description__, str)
        assert isinstance(__author__, str)
        assert isinstance(__license__, str)
        # These can be empty strings
        assert isinstance(__author_email__, str)
        assert isinstance(__url__, str)

    def test_version_info_matches_version(self) -> None:
        """Test that version_info matches version string."""
        from flext_ldap.__version__ import __version__, __version_info__

        version_parts = __version__.split(".")
        version_info_parts = [str(part) for part in __version_info__]

        # First few parts should match
        min_len = min(len(version_parts), len(version_info_parts))
        for i in range(min_len):
            assert version_parts[i] == version_info_parts[i], (
                f"Version part {i} mismatch: {version_parts[i]} != {version_info_parts[i]}"
            )

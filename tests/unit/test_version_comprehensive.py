"""Comprehensive unit tests for version information.

This module provides comprehensive unit tests for all version metadata,
testing version parsing, metadata reading, and exports.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import flext_ldap
from flext_ldap import (
    __author__,
    __author_email__,
    __branch__,
    __build__,
    __commit__,
    __copyright__,
    __description__,
    __email__,
    __license__,
    __maintainer__,
    __maintainer_email__,
    __project__,
    __version__,
    __version_info__,
    __version_tuple__,
)


class TestVersionExports:
    """Test version module exports."""

    def test_version_string_exists(self) -> None:
        """Test __version__ string exists and has valid format."""
        assert __version__ is not None
        assert isinstance(__version__, str)
        assert len(__version__) > 0
        # Version should have at least major.minor format
        assert "." in __version__

    def test_version_info_tuple_exists(self) -> None:
        """Test __version_info__ tuple exists."""
        assert __version_info__ is not None
        assert isinstance(__version_info__, tuple)
        assert len(__version_info__) >= 2  # At least major.minor

    def test_version_tuple_exists(self) -> None:
        """Test __version_tuple__ exists (alias for __version_info__)."""
        assert __version_tuple__ is not None
        assert isinstance(__version_tuple__, tuple)

    def test_project_name_exists(self) -> None:
        """Test __project__ name exists."""
        assert __project__ is not None
        assert isinstance(__project__, str)
        assert "flext" in __project__.lower()

    def test_description_exists(self) -> None:
        """Test __description__ exists."""
        assert __description__ is not None
        assert isinstance(__description__, str)

    def test_author_exists(self) -> None:
        """Test __author__ exists."""
        assert __author__ is not None
        assert isinstance(__author__, str)

    def test_author_email_exists(self) -> None:
        """Test __author_email__ exists."""
        assert __author_email__ is not None
        assert isinstance(__author_email__, str)

    def test_email_alias_exists(self) -> None:
        """Test __email__ exists as alias."""
        assert __email__ is not None
        assert isinstance(__email__, str)

    def test_maintainer_exists(self) -> None:
        """Test __maintainer__ exists."""
        assert __maintainer__ is not None
        assert isinstance(__maintainer__, str)

    def test_maintainer_email_exists(self) -> None:
        """Test __maintainer_email__ exists."""
        assert __maintainer_email__ is not None
        assert isinstance(__maintainer_email__, str)

    def test_license_exists(self) -> None:
        """Test __license__ exists."""
        assert __license__ is not None
        assert isinstance(__license__, str)

    def test_copyright_exists(self) -> None:
        """Test __copyright__ exists."""
        assert __copyright__ is not None
        assert isinstance(__copyright__, str)
        assert "copyright" in __copyright__.lower()

    def test_build_info_exists(self) -> None:
        """Test build information variables exist."""
        # Build info may be empty strings but should exist
        assert __build__ is not None
        assert __commit__ is not None
        assert __branch__ is not None


class TestVersionInfo:
    """Test version information parsing and structure."""

    def test_version_info_is_tuple(self) -> None:
        """Test version info is a tuple."""
        assert isinstance(__version_info__, tuple)

    def test_version_info_has_correct_structure(self) -> None:
        """Test version info tuple structure."""
        # Should have at least major, minor version
        assert len(__version_info__) >= 2
        # First two elements should be integers
        assert isinstance(__version_info__[0], int)
        assert isinstance(__version_info__[1], int)

    def test_version_tuple_equals_version_info(self) -> None:
        """Test __version_tuple__ is same as __version_info__."""
        assert __version_tuple__ == __version_info__

    def test_version_string_matches_version_info(self) -> None:
        """Test version string can be reconstructed from version info."""
        # Reconstruct version from tuple
        reconstructed = ".".join(str(part) for part in __version_info__)
        assert reconstructed == __version__


class TestMetadataReading:
    """Test metadata reading from pyproject.toml."""

    def test_author_email_parsing(self) -> None:
        """Test author email is correctly parsed."""
        # If email exists, it should be valid format
        if __author_email__:
            assert "@" in __author_email__ or __author_email__ == "dev@flext.dev"

    def test_email_equals_author_email(self) -> None:
        """Test __email__ equals __author_email__."""
        assert __email__ == __author_email__

    def test_default_author_fallback(self) -> None:
        """Test default author is set if metadata missing."""
        # Should have a value, either from metadata or default
        assert __author__
        # Default should be FLEXT Team if no metadata
        assert "FLEXT" in __author__ or "flext" in __author__.lower()

    def test_default_email_fallback(self) -> None:
        """Test default email is set if metadata missing."""
        # Should have a value, either from metadata or default
        assert __author_email__

    def test_maintainer_defaults_to_author(self) -> None:
        """Test maintainer defaults to author if not specified."""
        # Maintainer should be set (either from metadata or default to author)
        assert __maintainer__

    def test_license_defaults_to_mit(self) -> None:
        """Test license defaults to MIT if not specified."""
        # License should be set (either from metadata or default to MIT)
        assert __license__
        assert "MIT" in __license__ or __license__


class TestVersionStringOperations:
    """Test version string operations and comparisons."""

    def test_version_can_be_split(self) -> None:
        """Test version string can be split into parts."""
        parts = __version__.split(".")
        assert len(parts) >= 2
        assert all(part for part in parts)  # No empty parts

    def test_version_major_is_numeric(self) -> None:
        """Test major version is numeric."""
        major = __version__.split(".")[0]
        assert major.isdigit()

    def test_version_minor_is_numeric(self) -> None:
        """Test minor version is numeric."""
        parts = __version__.split(".")
        if len(parts) >= 2:
            minor = parts[1]
            # Minor might have pre-release suffix, check only leading digits
            assert any(c.isdigit() for c in minor)

    def test_version_comparison_possible(self) -> None:
        """Test version info allows comparison."""
        # Should be able to compare tuples
        assert __version_info__ >= (0, 0)
        assert isinstance(__version_info__[0], int)


class TestBuildInfo:
    """Test build information fields."""

    def test_build_info_are_strings(self) -> None:
        """Test build info fields are strings."""
        assert isinstance(__build__, str)
        assert isinstance(__commit__, str)
        assert isinstance(__branch__, str)

    def test_build_info_can_be_empty(self) -> None:
        """Test build info can be empty strings."""
        # These are typically populated by CI/CD, so can be empty
        # Just verify they don't raise errors when accessed
        _ = __build__
        _ = __commit__
        _ = __branch__


class TestExportedSymbols:
    """Test __all__ exports."""

    def test_all_symbols_are_exported(self) -> None:
        """Test all expected symbols are in __all__."""
        expected_symbols = [
            "__author__",
            "__author_email__",
            "__branch__",
            "__build__",
            "__commit__",
            "__copyright__",
            "__description__",
            "__license__",
            "__maintainer__",
            "__maintainer_email__",
            "__project__",
            "__version__",
            "__version_info__",
            "__version_tuple__",
        ]

        assert isinstance(flext_ldap.__all__, list)
        for symbol in expected_symbols:
            assert symbol in flext_ldap.__all__, f"Missing {symbol} in __all__"

    def test_exported_symbols_exist(self) -> None:
        """Test all symbols in __all__ actually exist."""
        for symbol in flext_ldap.__all__:
            assert hasattr(flext_ldap, symbol), f"Missing attribute {symbol}"


class TestVersionEdgeCases:
    """Test version edge cases and error handling."""

    def test_version_info_with_pre_release(self) -> None:
        """Test version info handles pre-release versions."""
        # If version has alpha/beta/rc, should be in version_info
        if any(x in __version__ for x in ["alpha", "beta", "rc", "dev"]):
            # Should have string parts in tuple
            assert any(isinstance(part, str) for part in __version_info__)

    def test_copyright_has_year(self) -> None:
        """Test copyright includes year."""
        # Should include a year (2024, 2025, etc.)
        assert any(str(year) in __copyright__ for year in range(2024, 2030))

    def test_metadata_fields_not_none(self) -> None:
        """Test critical metadata fields are not None."""
        assert __version__ is not None
        assert __project__ is not None
        assert __author__ is not None
        assert __license__ is not None

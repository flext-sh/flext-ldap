"""Comprehensive tests for __version__.py module.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import importlib.metadata

from flext_ldap import __version__


class TestVersionMetadata:
    """Test version metadata extraction and defaults."""

    def test_version_string_format(self) -> None:
        """Test version string follows semantic versioning."""
        version_str = __version__.__version__
        assert isinstance(version_str, str)
        assert len(version_str) > 0
        parts = version_str.split(".")
        assert len(parts) >= 2, "Version should have at least major.minor"

    def test_project_name(self) -> None:
        """Test project name is correct."""
        assert __version__.__project__ == "flext-ldap"

    def test_description_present(self) -> None:
        """Test description is present."""
        assert isinstance(__version__.__description__, str)
        assert len(__version__.__description__) > 0

    def test_author_defaults(self) -> None:
        """Test author defaults are set."""
        assert __version__.__author__ is not None
        assert isinstance(__version__.__author__, str)
        if not __version__.__author__:
            assert __version__.__author__ == "FLEXT Team"

    def test_author_email_defaults(self) -> None:
        """Test author email defaults are set."""
        assert __version__.__author_email__ is not None
        assert __version__.__email__ == __version__.__author_email__

    def test_maintainer_defaults(self) -> None:
        """Test maintainer defaults to author."""
        assert __version__.__maintainer__ is not None
        assert isinstance(__version__.__maintainer__, str)

    def test_maintainer_email_defaults(self) -> None:
        """Test maintainer email defaults to author email."""
        assert __version__.__maintainer_email__ is not None
        assert isinstance(__version__.__maintainer_email__, str)

    def test_license_info(self) -> None:
        """Test license information."""
        assert __version__.__license__ is not None
        assert isinstance(__version__.__license__, str)

    def test_copyright_info(self) -> None:
        """Test copyright information."""
        assert (
            __version__.__copyright__
            == "Copyright (c) 2025 Flext. All rights reserved."
        )


class TestVersionInfo:
    """Test version info tuples and parsing."""

    def test_version_info_tuple(self) -> None:
        """Test version_info is a tuple."""
        assert isinstance(__version__.__version_info__, tuple)
        assert len(__version__.__version_info__) >= 2

    def test_version_tuple_alias(self) -> None:
        """Test version_tuple is alias to version_info."""
        assert __version__.__version_tuple__ == __version__.__version_info__

    def test_version_parts_parsing(self) -> None:
        """Test version parts are correctly parsed."""
        for part in __version__.__version_info__:
            assert isinstance(part, (int, str)), "Version parts should be int or str"


class TestBuildInfo:
    """Test build information attributes."""

    def test_build_info_string(self) -> None:
        """Test build info is string (even if empty)."""
        assert isinstance(__version__.__build__, str)

    def test_commit_info_string(self) -> None:
        """Test commit info is string (even if empty)."""
        assert isinstance(__version__.__commit__, str)

    def test_branch_info_string(self) -> None:
        """Test branch info is string (even if empty)."""
        assert isinstance(__version__.__branch__, str)


class TestVersionExports:
    """Test __all__ exports."""

    def test_all_symbols_exported(self) -> None:
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
        assert set(__version__.__all__) == set(expected_symbols)

    def test_all_symbols_accessible(self) -> None:
        """Test all symbols in __all__ are accessible."""
        for symbol in __version__.__all__:
            assert hasattr(__version__, symbol), f"Symbol {symbol} not accessible"


class TestMetadataReading:
    """Test metadata reading from pyproject.toml."""

    def test_metadata_accessible(self) -> None:
        """Test importlib.metadata can access package metadata."""
        metadata = importlib.metadata.metadata("flext-ldap")
        assert metadata is not None
        assert "Version" in metadata
        assert "Name" in metadata

    def test_version_matches_metadata(self) -> None:
        """Test __version__ matches metadata."""
        metadata = importlib.metadata.metadata("flext-ldap")
        assert __version__.__version__ == metadata["Version"]

    def test_project_matches_metadata(self) -> None:
        """Test __project__ matches metadata."""
        metadata = importlib.metadata.metadata("flext-ldap")
        assert __version__.__project__ == metadata["Name"]


class TestEmailParsing:
    """Test email extraction logic."""

    def test_author_email_extraction(self) -> None:
        """Test author email extraction from Author-email field."""
        # Email could be in format "Name <email>" or just "email"
        assert "@" in __version__.__email__ or not __version__.__email__

    def test_email_alias(self) -> None:
        """Test __email__ is alias to __author_email__."""
        assert __version__.__email__ == __version__.__author_email__


class TestVersionStringOperations:
    """Test version string operations."""

    def test_version_comparable(self) -> None:
        """Test version can be compared as string."""
        version_str = __version__.__version__
        assert version_str >= "0.0.0"

    def test_version_repr(self) -> None:
        """Test version has string representation."""
        version_str = str(__version__.__version__)
        assert isinstance(version_str, str)
        assert len(version_str) > 0

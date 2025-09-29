"""Comprehensive tests for flext-ldap version module.

This module provides complete test coverage for the version module
following FLEXT standards with proper domain separation and centralized fixtures.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import importlib

import pytest

from flext_ldap import __version__

version_module = importlib.import_module("flext_ldap.__version__")


class TestFlextLdapVersion:
    """Comprehensive test suite for flext-ldap version module."""

    def test_version_attributes_exist(self) -> None:
        """Test that all version attributes exist."""
        assert hasattr(version_module, "__version__")
        assert hasattr(version_module, "__version_info__")
        assert hasattr(version_module, "__version_tuple__")
        assert hasattr(version_module, "__author__")
        assert hasattr(version_module, "__author_email__")
        assert hasattr(version_module, "__maintainer__")
        assert hasattr(version_module, "__maintainer_email__")
        assert hasattr(version_module, "__project__")
        assert hasattr(version_module, "__description__")
        assert hasattr(version_module, "__email__")
        assert hasattr(version_module, "__license__")
        assert hasattr(version_module, "__copyright__")
        assert hasattr(version_module, "__branch__")
        assert hasattr(version_module, "__build__")
        assert hasattr(version_module, "__commit__")

    def test_version_format(self) -> None:
        """Test that version follows semantic versioning."""
        version = version_module.__version__
        assert isinstance(version, str)
        assert len(version) > 0

        # Check if it follows semantic versioning pattern (major.minor.patch)
        parts = version.split(".")
        assert len(parts) >= 2  # At least major.minor

        # Check that parts are numeric
        for part in parts:
            assert (
                part.isdigit() or "+" in part or "-" in part
            )  # Allow for pre-release versions

    def test_version_info_format(self) -> None:
        """Test that version_info is properly formatted."""
        version_info = version_module.__version_info__
        assert isinstance(version_info, tuple)
        assert len(version_info) >= 2  # At least major, minor

        # Check that all parts are integers
        for part in version_info:
            assert isinstance(part, int)

    def test_version_tuple_format(self) -> None:
        """Test that version_tuple is properly formatted."""
        version_tuple = version_module.__version_tuple__
        assert isinstance(version_tuple, tuple)
        assert len(version_tuple) >= 2  # At least major, minor

        # Check that all parts are integers
        for part in version_tuple:
            assert isinstance(part, int)

    def test_author_information(self) -> None:
        """Test author information."""
        author = version_module.__author__
        author_email = version_module.__author_email__

        assert isinstance(author, str)
        assert len(author) > 0
        assert isinstance(author_email, str)
        assert len(author_email) > 0
        assert "@" in author_email

    def test_maintainer_information(self) -> None:
        """Test maintainer information."""
        maintainer = version_module.__maintainer__
        maintainer_email = version_module.__maintainer_email__

        assert isinstance(maintainer, str)
        assert len(maintainer) > 0
        assert isinstance(maintainer_email, str)
        assert len(maintainer_email) > 0
        assert "@" in maintainer_email

    def test_project_information(self) -> None:
        """Test project information."""
        project = version_module.__project__
        description = version_module.__description__
        email = version_module.__email__
        license_info = version_module.__license__
        copyright_info = version_module.__copyright__

        assert isinstance(project, str)
        assert len(project) > 0
        assert isinstance(description, str)
        assert len(description) > 0
        assert isinstance(email, str)
        assert len(email) > 0
        assert "@" in email
        assert isinstance(license_info, str)
        assert len(license_info) > 0
        assert isinstance(copyright_info, str)
        assert len(copyright_info) > 0

    def test_build_information(self) -> None:
        """Test build information."""
        branch = version_module.__branch__
        build = version_module.__build__
        commit = version_module.__commit__

        assert isinstance(branch, str)
        assert isinstance(build, str)
        assert isinstance(commit, str)
        # These can be empty for development builds

    def test_version_consistency(self) -> None:
        """Test version consistency between different formats."""
        version = version_module.__version__
        version_info = version_module.__version_info__
        version_tuple = version_module.__version_tuple__

        # Check that version_info and version_tuple are consistent
        assert version_info == version_tuple

        # Check that version string matches version_info
        version_parts = version.split(".")
        for i, part in enumerate(version_parts):
            if i < len(version_info):
                # Remove any pre-release identifiers for comparison
                clean_part = part.split("+")[0].split("-")[0]
                assert clean_part == str(version_info[i])

    def test_version_import(self) -> None:
        """Test that version can be imported from package."""
        assert __version__ is not None
        assert isinstance(__version__, str)

    def test_version_module_structure(self) -> None:
        """Test that version module has proper structure."""
        version_module = importlib.import_module("flext_ldap.__version__")

        # Check that module has expected attributes
        expected_attrs = [
            "__version__",
            "__version_info__",
            "__version_tuple__",
            "__author__",
            "__author_email__",
            "__maintainer__",
            "__maintainer_email__",
            "__project__",
            "__description__",
            "__email__",
            "__license__",
            "__copyright__",
            "__branch__",
            "__build__",
            "__commit__",
        ]

        for attr in expected_attrs:
            assert hasattr(version_module, attr), f"Missing attribute: {attr}"

    def test_version_string_representation(self) -> None:
        """Test that version string representation is valid."""
        version = version_module.__version__

        # Should not be empty
        assert version

        # Should not contain only whitespace
        assert version.strip()

        # Should not contain newlines
        assert "\n" not in version
        assert "\r" not in version

    def test_version_info_types(self) -> None:
        """Test that version_info contains correct types."""
        version_info = version_module.__version_info__

        # Should be a tuple
        assert isinstance(version_info, tuple)

        # Should have at least 2 elements (major, minor)
        assert len(version_info) >= 2

        # All elements should be integers
        for part in version_info:
            assert isinstance(part, int)
            assert part >= 0  # Version numbers should be non-negative

    def test_version_tuple_types(self) -> None:
        """Test that version_tuple contains correct types."""
        version_tuple = version_module.__version_tuple__

        # Should be a tuple
        assert isinstance(version_tuple, tuple)

        # Should have at least 2 elements (major, minor)
        assert len(version_tuple) >= 2

        # All elements should be integers
        for part in version_tuple:
            assert isinstance(part, int)
            assert part >= 0  # Version numbers should be non-negative

    def test_email_format_validation(self) -> None:
        """Test that email addresses are properly formatted."""
        emails = [
            version_module.__author_email__,
            version_module.__maintainer_email__,
            version_module.__email__,
        ]

        for email in emails:
            assert isinstance(email, str)
            assert len(email) > 0
            assert "@" in email
            assert "." in email.split("@")[1]  # Domain should have a dot

    def test_copyright_format(self) -> None:
        """Test that copyright information is properly formatted."""
        copyright_info = version_module.__copyright__

        assert isinstance(copyright_info, str)
        assert len(copyright_info) > 0
        assert "©" in copyright_info or "Copyright" in copyright_info

    def test_license_format(self) -> None:
        """Test that license information is properly formatted."""
        license_info = version_module.__license__

        assert isinstance(license_info, str)
        assert len(license_info) > 0
        assert license_info.upper() in {"MIT", "APACHE", "GPL", "BSD", "PROPRIETARY"}

    def test_project_name_format(self) -> None:
        """Test that project name is properly formatted."""
        project = version_module.__project__

        assert isinstance(project, str)
        assert len(project) > 0
        assert "flext" in project.lower()  # Should contain flext
        assert "ldap" in project.lower()  # Should contain ldap

    def test_description_format(self) -> None:
        """Test that description is properly formatted."""
        description = version_module.__description__

        assert isinstance(description, str)
        assert len(description) > 0
        assert len(description) > 10  # Should be descriptive

    def test_branch_format(self) -> None:
        """Test that branch information is properly formatted."""
        branch = version_module.__branch__

        assert isinstance(branch, str)
        # Branch can be empty for development builds
        if len(branch) > 0:
            assert branch in {"main", "master", "develop", "dev"} or branch.startswith(
                (
                    "feature/",
                    "release/",
                )
            )

    def test_build_format(self) -> None:
        """Test that build information is properly formatted."""
        build = version_module.__build__

        assert isinstance(build, str)
        # Build can be empty for development builds
        if len(build) > 0:
            # Should be a build number or identifier
            assert build.isdigit() or len(build) > 3

    def test_commit_format(self) -> None:
        """Test that commit information is properly formatted."""
        commit = version_module.__commit__

        assert isinstance(commit, str)
        # Commit can be empty for development builds
        if len(commit) > 0:
            # Should be a commit hash (at least 7 characters)
            assert len(commit) >= 7

    def test_version_module_imports(self) -> None:
        """Test that version module can be imported without errors."""
        try:
            importlib.import_module("flext_ldap.__version__")
            assert True
        except ImportError as e:
            pytest.fail(f"Failed to import version module: {e}")

    def test_version_attributes_immutable(self) -> None:
        """Test that version attributes are immutable."""
        version = version_module.__version__
        version_info = version_module.__version_info__
        version_tuple = version_module.__version_tuple__

        # These should be immutable
        assert isinstance(version, str)
        assert isinstance(version_info, tuple)
        assert isinstance(version_tuple, tuple)

    def test_version_comparison(self) -> None:
        """Test version comparison functionality."""
        version_info = version_module.__version_info__

        # Should be able to compare versions
        assert version_info >= (0, 0, 0)  # Should be at least 0.0.0
        assert version_info[0] >= 0  # Major version should be non-negative
        assert version_info[1] >= 0  # Minor version should be non-negative

    def test_version_string_parsing(self) -> None:
        """Test that version string can be parsed correctly."""
        version = version_module.__version__
        version_info = version_module.__version_info__

        # Parse version string
        parts = version.split(".")

        # Check that parsed parts match version_info
        for i, part in enumerate(parts):
            if i < len(version_info):
                # Remove any pre-release identifiers
                clean_part = part.split("+")[0].split("-")[0]
                assert clean_part == str(version_info[i])

    def test_version_module_docstring(self) -> None:
        """Test that version module has proper docstring."""
        version_module = importlib.import_module("flext_ldap.__version__")

        assert version_module.__doc__ is not None
        assert len(version_module.__doc__) > 0
        assert "version" in version_module.__doc__.lower()

    def test_version_export_completeness(self) -> None:
        """Test that all version information is properly exported."""
        version_module = importlib.import_module("flext_ldap.__version__")

        # Check that all expected variables are available
        expected_vars = [
            "__version__",
            "__version_info__",
            "__version_tuple__",
            "__author__",
            "__author_email__",
            "__maintainer__",
            "__maintainer_email__",
            "__project__",
            "__description__",
            "__email__",
            "__license__",
            "__copyright__",
            "__branch__",
            "__build__",
            "__commit__",
        ]

        for var in expected_vars:
            assert hasattr(version_module, var), f"Missing exported variable: {var}"

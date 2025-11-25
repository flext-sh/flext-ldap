"""Unit tests for version and package metadata.

**Modules Tested:**
- flext_ldap.__version__: Package version and metadata exports

**Scope:**
- Version string format and validation (semantic versioning)
- Version info tuple structure and consistency
- Package metadata completeness (title, description, author, license, URLs)
- Version string and version_info tuple alignment
- Metadata type validation

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar

import pytest

from flext_ldap.__version__ import (
    __author__,
    __author_email__,
    __description__,
    __license__,
    __title__,
    __url__,
    __version__,
    __version_info__,
)
from tests.fixtures.general_constants import General

pytestmark = pytest.mark.unit


class MetadataProperty(StrEnum):
    """Metadata properties to validate."""

    TITLE = "title"
    DESCRIPTION = "description"
    AUTHOR = "author"
    LICENSE = "license"
    AUTHOR_EMAIL = "author_email"
    URL = "url"


class TestFlextLdapVersion:
    """Tests for version and package metadata with comprehensive validation.

    Single class with flat test methods covering:
    - Version string format and semantic versioning validation
    - Version info tuple structure and consistency
    - Package metadata completeness and type safety
    - Version consistency between string and tuple formats
    """

    # Metadata properties for parametrization
    METADATA_PROPERTIES: ClassVar[tuple[MetadataProperty, ...]] = (
        MetadataProperty.TITLE,
        MetadataProperty.DESCRIPTION,
        MetadataProperty.AUTHOR,
        MetadataProperty.LICENSE,
        MetadataProperty.AUTHOR_EMAIL,
        MetadataProperty.URL,
    )

    # Metadata property mapping for parametrized tests
    METADATA_VALUES: ClassVar[dict[MetadataProperty, str]] = {
        MetadataProperty.TITLE: __title__,
        MetadataProperty.DESCRIPTION: __description__,
        MetadataProperty.AUTHOR: __author__,
        MetadataProperty.LICENSE: __license__,
        MetadataProperty.AUTHOR_EMAIL: __author_email__,
        MetadataProperty.URL: __url__,
    }

    # Required metadata mapping for validation
    REQUIRED_METADATA: ClassVar[dict[str, str]] = {
        "__title__": __title__,
        "__description__": __description__,
        "__author__": __author__,
        "__license__": __license__,
        "__author_email__": __author_email__,
        "__url__": __url__,
    }

    @staticmethod
    def _get_version_parts(version_string: str = __version__) -> list[str]:
        """Get version string parts by splitting on dot."""
        return version_string.split(".")

    @staticmethod
    def _get_version_info_parts(
        version_tuple: tuple[object, ...] = __version_info__,
    ) -> list[str]:
        """Get version info parts as strings."""
        return [str(part) for part in version_tuple]

    @staticmethod
    def _is_semver_valid(
        version_string: str = __version__,
        min_parts: int = General.VERSION_MIN_PARTS,
    ) -> bool:
        """Check if version string has minimum required semver parts."""
        parts = version_string.split(".")
        return len(parts) >= min_parts and all(len(part) > 0 for part in parts)

    def test_version_is_non_empty_string(self) -> None:
        """Test that __version__ is a non-empty string."""
        assert isinstance(__version__, str)
        assert len(__version__) > 0

    @pytest.mark.parametrize(
        "min_parts",
        [General.VERSION_MIN_PARTS, General.VERSION_MAX_PARTS],
    )
    def test_version_has_valid_semver_parts(self, min_parts: int) -> None:
        """Test version has valid semver parts (parametrized with 2, 3)."""
        assert self._is_semver_valid(__version__, min_parts), (
            f"Version '{__version__}' should have at least {min_parts} parts"
        )

    def test_version_info_is_tuple(self) -> None:
        """Test that __version_info__ is a non-empty tuple."""
        assert isinstance(__version_info__, tuple)
        assert len(__version_info__) >= General.VERSION_MIN_COMPONENTS

    def test_version_info_parts_are_integers(self) -> None:
        """Test that all version_info parts are integers."""
        for i, part in enumerate(__version_info__):
            assert isinstance(part, int), (
                f"Version info part {i} (value={part}) is not an integer"
            )

    def test_version_string_matches_version_info(self) -> None:
        """Test that version string matches version_info tuple."""
        version_parts = self._get_version_parts()
        version_info_parts = self._get_version_info_parts()

        # Compare only up to minimum length
        min_len = min(len(version_parts), len(version_info_parts))
        for i in range(min_len):
            assert version_parts[i] == version_info_parts[i], (
                f"Version mismatch at part {i}: "
                f"'{version_parts[i]}' (from __version__) != "
                f"'{version_info_parts[i]}' (from __version_info__)"
            )

    @pytest.mark.parametrize("property_name", METADATA_PROPERTIES)
    def test_metadata_property_is_non_empty_string(
        self, property_name: MetadataProperty
    ) -> None:
        """Test that each metadata property is a non-empty string (parametrized)."""
        property_value = self.METADATA_VALUES[property_name]
        assert isinstance(property_value, str), (
            f"Metadata property '{property_name}' is not a string"
        )
        assert len(property_value) > 0, f"Metadata property '{property_name}' is empty"

    def test_all_required_metadata_present(self) -> None:
        """Test that all required metadata properties are defined and non-empty."""
        for name, value in self.REQUIRED_METADATA.items():
            assert isinstance(value, str), f"{name} is not a string"
            assert len(value) > 0, f"{name} is empty"

    def test_version_length_reasonable(self) -> None:
        """Test that version string length is reasonable."""
        assert (
            General.VERSION_MIN_LENGTH <= len(__version__) <= General.VERSION_MAX_LENGTH
        ), f"Version string '{__version__}' has unusual length"

    def test_version_info_has_at_least_major_minor(self) -> None:
        """Test that version_info contains at least major and minor version numbers."""
        assert len(__version_info__) >= General.VERSION_MIN_COMPONENTS, (
            "version_info must have at least 2 components (major, minor)"
        )
        major, minor = __version_info__[0], __version_info__[1]
        assert isinstance(major, int) and major >= 0, (
            "Major version must be non-negative int"
        )
        assert isinstance(minor, int) and minor >= 0, (
            "Minor version must be non-negative int"
        )

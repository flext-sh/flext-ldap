"""🏷️ LDAP Core Shared - Version and Release Information.

Semantic versioning and release metadata for the LDAP Core Shared library.
Compatible with Python 3.9+ and following semantic versioning standards.
"""

from __future__ import annotations

from typing import NamedTuple

# Semantic version components
MAJOR = 1  # Breaking changes
MINOR = 0  # New features (backwards compatible)
PATCH = 0  # Bug fixes (backwards compatible)

# Pre-release identifiers (empty for stable releases)
# Examples: "alpha", "beta", "rc", "dev"
PRE_RELEASE = ""
PRE_RELEASE_NUMBER = 0

# Build metadata (optional)
BUILD_METADATA = ""

# Version tuple for programmatic access
VERSION_TUPLE = (MAJOR, MINOR, PATCH)


class VersionInfo(NamedTuple):
    """Version information structure."""

    major: int
    minor: int
    patch: int
    pre_release: str
    pre_release_number: int
    build_metadata: str


# Version information instance
VERSION_INFO = VersionInfo(
    major=MAJOR,
    minor=MINOR,
    patch=PATCH,
    pre_release=PRE_RELEASE,
    pre_release_number=PRE_RELEASE_NUMBER,
    build_metadata=BUILD_METADATA,
)


def get_version() -> str:
    """Get formatted version string.

    Returns:
        Semantic version string (e.g., "1.0.0", "1.0.0-alpha.1", "1.0.0+build.123")
    """
    version = f"{MAJOR}.{MINOR}.{PATCH}"

    # Add pre-release identifier if present
    if PRE_RELEASE:
        version += f"-{PRE_RELEASE}"
        if PRE_RELEASE_NUMBER > 0:
            version += f".{PRE_RELEASE_NUMBER}"

    # Add build metadata if present
    if BUILD_METADATA:
        version += f"+{BUILD_METADATA}"

    return version


def get_version_tuple() -> tuple[int, int, int]:
    """Get version as tuple for comparison.

    Returns:
        Version tuple (major, minor, patch)
    """
    return VERSION_TUPLE


def is_stable_release() -> bool:
    """Check if this is a stable release.

    Returns:
        True if stable (no pre-release identifier)
    """
    return not PRE_RELEASE


def is_compatible_python_version(python_version: tuple[int, int]) -> bool:
    """Check if Python version is compatible.

    Args:
        python_version: Python version tuple (major, minor)

    Returns:
        True if compatible with this library
    """
    min_python = (3, 9)
    max_python = (4, 0)  # Exclusive upper bound

    return min_python <= python_version < max_python


# Version string for easy access
__version__ = get_version()

# Compatibility information
PYTHON_REQUIRES = ">=3.9,<4.0"
SUPPORTED_PYTHON_VERSIONS = [
    "3.9",
    "3.10",
    "3.11",
    "3.12",
    "3.13",
]

# Release information
RELEASE_DATE = "2025-06-25"
RELEASE_NAME = "Enterprise Foundation"
RELEASE_NOTES_URL = (
    "https://github.com/ldap-core/ldap-core-shared/releases/tag/v{version}"
)

# Development status classifiers
DEVELOPMENT_STATUS = "5 - Production/Stable"
INTENDED_AUDIENCE = [
    "Developers",
    "System Administrators",
    "Information Technology",
]

# Package metadata
PACKAGE_NAME = "ldap-core-shared"
PACKAGE_DESCRIPTION = "Enterprise Python LDAP library with async-first design"
PACKAGE_URL = "https://github.com/ldap-core/ldap-core-shared"
DOCUMENTATION_URL = "https://ldap-core-shared.readthedocs.io"
ISSUES_URL = "https://github.com/ldap-core/ldap-core-shared/issues"
CHANGELOG_URL = "https://github.com/ldap-core/ldap-core-shared/blob/main/CHANGELOG.md"

# License information
LICENSE = "MIT"
LICENSE_URL = "https://opensource.org/licenses/MIT"

# Author information
AUTHOR = "LDAP Core Team"
AUTHOR_EMAIL = "team@ldap-core.com"
MAINTAINER = AUTHOR
MAINTAINER_EMAIL = AUTHOR_EMAIL

# Keywords for package discovery
KEYWORDS = [
    "ldap",
    "directory",
    "enterprise",
    "async",
    "migration",
    "schema",
    "ldif",
    "oracle",
    "active-directory",
    "authentication",
    "python39",
    "python310",
    "python311",
    "python312",
    "python313",
]

# PyPI classifiers
CLASSIFIERS = (
    [
        f"Development Status :: {DEVELOPMENT_STATUS}",
        "Framework :: AsyncIO",
        "Framework :: Pydantic",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        f"License :: OSI Approved :: {LICENSE} License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
    ]
    + [
        f"Programming Language :: Python :: {version}"
        for version in SUPPORTED_PYTHON_VERSIONS
    ]
    + [
        "Topic :: Internet",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
        "Topic :: System :: Systems Administration :: LDAP",
        "Typing :: Typed",
    ]
)


def get_package_info() -> dict[str, str | list[str] | bool]:
    """Get complete package information dictionary.

    Returns:
        Package metadata dictionary
    """
    return {
        "name": PACKAGE_NAME,
        "version": __version__,
        "description": PACKAGE_DESCRIPTION,
        "url": PACKAGE_URL,
        "documentation_url": DOCUMENTATION_URL,
        "author": AUTHOR,
        "author_email": AUTHOR_EMAIL,
        "maintainer": MAINTAINER,
        "maintainer_email": MAINTAINER_EMAIL,
        "license": LICENSE,
        "license_url": LICENSE_URL,
        "python_requires": PYTHON_REQUIRES,
        "supported_python_versions": SUPPORTED_PYTHON_VERSIONS,
        "keywords": KEYWORDS,
        "classifiers": CLASSIFIERS,
        "release_date": RELEASE_DATE,
        "release_name": RELEASE_NAME,
        "development_status": DEVELOPMENT_STATUS,
        "is_stable": is_stable_release(),
    }

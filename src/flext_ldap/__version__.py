"""Version and package metadata using importlib.metadata.

Single source of truth for version info from pyproject.toml following
flext-core standards via importlib.metadata.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from importlib.metadata import metadata

_metadata = metadata("flext_ldap")

__version__ = _metadata["Version"]
__version_info__ = tuple(
    int(part) if part.isdigit() else part for part in __version__.split(".")
)
__title__ = _metadata["Name"]
__description__ = _metadata["Summary"]
__author__ = _metadata["Author"]
__author_email__ = _metadata["Author-Email"]
__license__ = _metadata["License"]
__url__ = _metadata.get("Home-Page") or ""

__all__ = [
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__title__",
    "__url__",
    "__version__",
    "__version_info__",
]

"""Version and package metadata using importlib.metadata.

Single source of truth pattern following flext-core standards.
All metadata comes from pyproject.toml via importlib.metadata.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from importlib.metadata import metadata

_metadata = metadata("flext-ldap")

__version__: str = _metadata.get("Version", "0.0.0")
__version_info__: tuple[int | str, ...] = tuple(
    int(part) if part.isdigit() else part for part in __version__.split(".")
)
__title__: str = _metadata.get("Name", "flext-ldap")
__description__: str = _metadata.get("Summary", "FLEXT LDAP Client Library")
__author__: str = _metadata.get("Author", "FLEXT Team")
__author_email__: str = _metadata.get("Author-Email", "")
__license__: str = _metadata.get("License", "MIT")
__url__: str = _metadata.get("Homepage", "https://github.com/flext-sh/flext")

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

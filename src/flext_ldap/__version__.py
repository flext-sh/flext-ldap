"""Version information for flext-ldap.

This file reads version from pyproject.toml metadata.
All version references should import from this file.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import importlib.metadata
from typing import cast

_metadata: dict[str, object] = cast(
    "dict[str, object]", importlib.metadata.metadata("flext-ldap")
)
__version__: str = cast("str", _metadata["Version"])
__project__: str = cast("str", _metadata["Name"])
__description__: str = cast("str", _metadata["Summary"])
__author__: str = cast("str", _metadata["Author"])
__author_email__: str = (
    cast("str", _metadata["Author-email"]).split("<")[1].rstrip(">")
    if "<" in cast("str", _metadata.get("Author-email", ""))
    else ""
)
__email__: str = __author_email__

# Ensure sensible defaults when metadata is missing in editable installs
if not __author__:
    __author__ = "FLEXT Team"
if not __author_email__:
    __author_email__ = "dev@flext.dev"
    __email__ = __author_email__
__maintainer__: str = cast("str", _metadata.get("Maintainer", __author__))
__maintainer_email__: str = cast(
    "str", _metadata.get("Maintainer-email", __author_email__)
)
__license__: str = cast("str", _metadata.get("License", "MIT"))

# Parse version info
_parts: list[str] = __version__.split(".")
__version_info__: tuple[int | str, ...] = tuple(
    int(p) if p.isdigit() else p for p in _parts
)
__version_tuple__: tuple[int | str, ...] = __version_info__

# Fixed metadata
__copyright__ = "Copyright (c) 2025 Flext. All rights reserved."

# Build information (can be populated by CI/CD)
__build__ = ""
__commit__ = ""
__branch__ = ""

# All exported symbols
__all__ = [
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

# Version attributes are available through explicit import

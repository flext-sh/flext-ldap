# AUTO-GENERATED FILE — Regenerate with: make gen
"""Package version and metadata for flext-ldap.

Subclass of ``FlextVersion`` — overrides only ``_metadata``.
All derived attributes (``__version__``, ``__title__``, etc.) are
computed automatically via ``FlextVersion.__init_subclass__``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from importlib.metadata import PackageMetadata, metadata

from flext_core.__version__ import FlextVersion


class FlextLdapVersion(FlextVersion):
    """flext-ldap version — MRO-derived from FlextVersion."""

    _metadata: PackageMetadata = metadata("flext-ldap")


__version__ = FlextLdapVersion.__version__
__version_info__ = FlextLdapVersion.__version_info__
__title__ = FlextLdapVersion.__title__
__description__ = FlextLdapVersion.__description__
__author__ = FlextLdapVersion.__author__
__author_email__ = FlextLdapVersion.__author_email__
__license__ = FlextLdapVersion.__license__
__url__ = FlextLdapVersion.__url__
__all__: list[str] = [
    "FlextLdapVersion",
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__title__",
    "__url__",
    "__version__",
    "__version_info__",
]

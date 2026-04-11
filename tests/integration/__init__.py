# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldap package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if _t.TYPE_CHECKING:
    from flext_ldap.test_smoke import TestsFlextLdapSmoke, pytestmark
_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".test_smoke": (
            "TestsFlextLdapSmoke",
            "pytestmark",
        ),
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)

__all__ = [
    "TestsFlextLdapSmoke",
    "pytestmark",
]

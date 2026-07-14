# AUTO-GENERATED FILE — canonical lazy tests facade. Regenerate with: make gen
"""Test package facade exposing the project test aliases lazily."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from tests.base import (
        TestsFlextLdapServiceBase as TestsFlextLdapServiceBase,
        s as s,
    )
    from tests.constants import (
        TestsFlextLdapConstants as TestsFlextLdapConstants,
        c as c,
    )
    from tests.models import TestsFlextLdapModels as TestsFlextLdapModels, m as m
    from tests.protocols import (
        TestsFlextLdapProtocols as TestsFlextLdapProtocols,
        p,
    )
    from tests.typings import TestsFlextLdapTypes as TestsFlextLdapTypes, t as t
    from tests.utilities import (
        TestsFlextLdapUtilities as TestsFlextLdapUtilities,
        u,
    )

_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".constants": ("TestsFlextLdapConstants", "c"),
        ".typings": ("TestsFlextLdapTypes", "t"),
        ".protocols": ("TestsFlextLdapProtocols", "p"),
        ".models": ("TestsFlextLdapModels", "m"),
        ".utilities": ("TestsFlextLdapUtilities", "u"),
        ".base": ("TestsFlextLdapServiceBase", "s"),
    },
)

install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)

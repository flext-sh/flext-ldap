"""Test infrastructure for flext-ldap tests.

Provides centralized test objects that extend production modules from src/flext_ldap/.
All test objects use real inheritance to expose the full hierarchy without duplication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

# Core test modules extending src modules (using standardized short names)
# These use the SAME short names as production (m, t, u, c, p, s) for consistency
from flext_core import (
    FlextDecorators as d,
    FlextExceptions as e,
    FlextMixins as x,
    FlextResult as r,
)

from tests.base import TestsFlextLdapServiceBase as s
from tests.constants import TestsFlextLdapConstants as c
from tests.models import TestsFlextLdapModels as m
from tests.protocols import TestsFlextLdapProtocols as p
from tests.typings import TestsFlextLdapTypes as t
from tests.utilities import TestsFlextLdapUtilities as u

# Export classes for type checking
TestsFlextLdapConstants = c
TestsFlextLdapModels = m
TestsFlextLdapProtocols = p
TestsFlextLdapServiceBase = s
TestsFlextLdapTypes = t
TestsFlextLdapUtilities = u

__all__ = [
    "TestsFlextLdapConstants",
    "TestsFlextLdapModels",
    "TestsFlextLdapProtocols",
    "TestsFlextLdapServiceBase",
    "TestsFlextLdapTypes",
    "TestsFlextLdapUtilities",
    "Testsc",
    "Testsp",
    "Testst",
    "Testsu",
    "c",
    "d",
    "e",
    "m",
    "p",
    "r",
    "s",
    "t",
    "u",
    "x",
]

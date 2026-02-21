"""Test infrastructure for flext-ldap tests.

Provides centralized test objects that extend production modules from src/flext_ldap/.
All test objects use real inheritance to expose the full hierarchy without duplication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import (
    FlextDecorators as d,
    FlextExceptions as e,
    FlextMixins as x,
    r,
)

from tests.base import TestsFlextLdapServiceBase, TestsFlextLdapServiceBase as s
from tests.constants import TestsFlextLdapConstants, TestsFlextLdapConstants as c
from tests.models import TestsFlextLdapModels, TestsFlextLdapModels as m
from tests.protocols import TestsFlextLdapProtocols, p, tp
from tests.typings import TestsFlextLdapTypes, TestsFlextLdapTypes as t, tt
from tests.utilities import TestsFlextLdapUtilities, TestsFlextLdapUtilities as u

__all__ = [
    "TestsFlextLdapConstants",
    "TestsFlextLdapModels",
    "TestsFlextLdapProtocols",
    "TestsFlextLdapServiceBase",
    "TestsFlextLdapTypes",
    "TestsFlextLdapUtilities",
    "c",
    "d",
    "e",
    "m",
    "p",
    "r",
    "s",
    "t",
    "tp",
    "tt",
    "u",
    "x",
]

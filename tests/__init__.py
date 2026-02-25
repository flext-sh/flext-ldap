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
    r,
    x,
)

from .base import TestsFlextLdapServiceBase, TestsFlextLdapServiceBase as s
from .constants import TestsFlextLdapConstants, TestsFlextLdapConstants as c
from .models import TestsFlextLdapModels, TestsFlextLdapModels as m
from .protocols import TestsFlextLdapProtocols, p
from .typings import TestsFlextLdapTypes, TestsFlextLdapTypes as t, tt
from .utilities import TestsFlextLdapUtilities, TestsFlextLdapUtilities as u

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
    "tt",
    "u",
    "x",
]

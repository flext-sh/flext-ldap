"""FLEXT-LDAP - LDAP Client Library.

LDAP client library with RFC compliance and server-specific quirks
for the FLEXT ecosystem. Reuses flext-ldif for Entry models and parsing.

Single Entry Point Architecture:
    This module enforces a single entry point pattern. ALL LDAP operations must
    go through the FlextLdap class. Internal modules (adapters, services) are
    NOT part of the public API and should not be imported directly by consumers.

    Correct usage:
        from flext_ldap import FlextLdap
        ldap = FlextLdap()
        result = ldap.search(options)

    Incorrect usage (bypasses single entry point):
        from flext_ldap.services.connection import FlextLdapConnection  # ❌ WRONG
        from flext_ldap.adapters import Ldap3Adapter  # ❌ WRONG

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import (
    FlextDecorators as d,
    FlextExceptions as e,
    FlextHandlers as h,
    FlextMixins as x,
    r,
)

from flext_ldap.api import FlextLdap
from flext_ldap.base import FlextLdapServiceBase, s
from flext_ldap.constants import FlextLdapConstants, c
from flext_ldap.models import FlextLdapModels, m
from flext_ldap.protocols import FlextLdapProtocols, p
from flext_ldap.services.connection import FlextLdapConnection
from flext_ldap.services.detection import FlextLdapServerDetector
from flext_ldap.services.operations import FlextLdapOperations
from flext_ldap.settings import FlextLdapSettings
from flext_ldap.typings import FlextLdapTypes, t
from flext_ldap.utilities import FlextLdapUtilities, u

# ═══════════════════════════════════════════════════════════════════════════
# CONVENIENCE ALIASES - Short names for common usage
# ═══════════════════════════════════════════════════════════════════════════
# Domain aliases imported from modules (u, t, c, m, p, s):
#   u = FlextLdapUtilities (from utilities.py)
#   t = FlextLdapTypes (from typings.py)
#   c = FlextLdapConstants (from constants.py)
#   m = FlextLdapModels (from models.py)
#   p = FlextLdapProtocols (from protocols.py)
#   s = FlextLdapServiceBase (from base.py)
#
# Global aliases from flext-core (r, e, d, x, h):
#   r = FlextResult
#   e = FlextExceptions
#   d = FlextDecorators
#   x = FlextMixins
#   h = FlextHandlers
#
# Usage:
#   from flext_ldap import u, t, c, m, p, r, e, d, s, x, h
#   result = {k: v for k, v in data.items() if predicate(k, v)}
#   typed_value: t.Ldap.Operation.Attributes = {...}
#   status = c.OperationType.ADD
#   model = m.SearchOptions(...)
#   protocol: p.LdapEntry.EntryProtocol = entry
#   success = r.ok("value")
#   error = e.ValidationError("message")
#   decorator = d.validate()
#   class MyService(s): ...  # s = FlextLdapServiceBase
#   mixin = x.Cacheable()
#   handler = h.CommandHandler()

# Domain aliases imported from modules (already imported above)
# u, t, c, m, p, s are imported from their respective modules
# Global aliases r, e, d, x, h imported from flext_core via import-as above

__all__ = [
    "FlextLdap",  # ✅ Facade (single entry point)
    "FlextLdapConnection",  # ✅ Connection service
    "FlextLdapConstants",  # ✅ Constants
    "FlextLdapModels",  # ✅ Domain models
    "FlextLdapOperations",  # ✅ Operations service
    "FlextLdapProtocols",  # ✅ Protocol definitions
    "FlextLdapServerDetector",  # ✅ Server detection service
    "FlextLdapServiceBase",  # ✅ Base class for services with typed config
    "FlextLdapSettings",  # ✅ Configuration
    "FlextLdapTypes",  # ✅ Type definitions
    "FlextLdapUtilities",  # ✅ Advanced utilities
    "c",  # ✅ Constants alias
    "d",  # ✅ Decorators alias
    "e",  # ✅ Exceptions alias
    "h",  # ✅ Handlers alias
    "m",  # ✅ Models alias
    "p",  # ✅ Protocols alias
    "r",  # ✅ Result alias
    "s",  # ✅ Service alias
    "t",  # ✅ Types alias
    "u",  # ✅ Utilities alias
    "x",  # ✅ Mixins alias
]

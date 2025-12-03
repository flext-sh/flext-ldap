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
    FlextDecorators,
    FlextExceptions,
    FlextHandlers,
    FlextMixins,
    FlextResult,
    FlextService,
)

from flext_ldap.api import FlextLdap
from flext_ldap.base import FlextLdapServiceBase
from flext_ldap.config import FlextLdapConfig
from flext_ldap.constants import FlextLdapConstants
from flext_ldap.models import FlextLdapModels
from flext_ldap.protocols import FlextLdapProtocols
from flext_ldap.services.detection import FlextLdapServerDetector
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.utilities import FlextLdapUtilities

__email__ = "dev@flext.com"

# ═══════════════════════════════════════════════════════════════════════════
# CONVENIENCE ALIASES - Short names for common usage
# ═══════════════════════════════════════════════════════════════════════════
# Use these aliases for concise code:
#   from flext_ldap import u, t, c, m, p, r, e, d, s, x, h
#   result = u.filter(data, predicate)
#   typed_value: t.Ldap.Attributes = {...}
#   status = c.OperationType.ADD
#   model = m.SearchOptions(...)
#   protocol: p.LdapEntry.EntryProtocol = entry
#   success = r.ok("value")
#   error = e.ValidationError("message")
#   decorator = d.validate()
#   class MyService(s): ...  # s = FlextService base class
#   mixin = x.Cacheable()
#   handler = h.CommandHandler()

u = FlextLdapUtilities
t = FlextLdapTypes
c = FlextLdapConstants
m = FlextLdapModels
p = FlextLdapProtocols
r = FlextResult
e = FlextExceptions
d = FlextDecorators
s = FlextService
x = FlextMixins
h = FlextHandlers

__all__ = [
    "FlextLdap",  # ✅ Facade (single entry point)
    "FlextLdapConfig",  # ✅ Configuration
    "FlextLdapConstants",  # ✅ Constants
    "FlextLdapModels",  # ✅ Domain models
    "FlextLdapProtocols",  # ✅ Protocol definitions
    "FlextLdapServerDetector",  # ✅ Server detection service
    "FlextLdapServiceBase",  # ✅ Base class for services with typed config
    "FlextLdapTypes",  # ✅ Type definitions
    "FlextLdapUtilities",  # ✅ Advanced utilities
    # Convenience aliases
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

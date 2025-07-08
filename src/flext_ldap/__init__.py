# Copyright (c) 2025 FLEXT
# SPDX-License-Identifier: MIT

"""FLEXT LDAP - Enterprise LDAP Operations Library.

Clean, minimal implementation following SOLID/KISS/DRY principles.
Integrated with flext-core for maximum code reuse and minimal duplication.
"""

from __future__ import annotations

from flext_ldap.client import LDAPClient
from flext_ldap.models import LDAPEntry, LDAPFilter, LDAPScope

__version__ = "1.0.0"
__all__ = ["LDAPClient", "LDAPEntry", "LDAPFilter", "LDAPScope"]

"""ACL Management Module for FLEXT LDAP.

This module provides comprehensive ACL (Access Control List) management
capabilities across different LDAP server types including OpenLDAP, Oracle
Directory, 389 DS, Apache DS, and Active Directory.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap.acl.constants import FlextLdapAclConstants
from flext_ldap.acl.converters import FlextLdapAclConverters
from flext_ldap.acl.manager import FlextLdapAclManager
from flext_ldap.acl.parsers import FlextLdapAclParsers
from flext_ldap.models import FlextLdapModels

FlextLdapAclModels = FlextLdapModels

__all__ = [
    "FlextLdapAclConstants",
    "FlextLdapAclConverters",
    "FlextLdapAclManager",
    "FlextLdapAclModels",
    "FlextLdapAclParsers",
]

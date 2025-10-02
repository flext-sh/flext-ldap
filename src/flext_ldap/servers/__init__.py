"""Server-specific LDAP operations implementations.

This package provides server-specific operations for different LDAP implementations,
including complete implementations for OpenLDAP, Oracle OID/OUD, and stubs for
other servers.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldap.servers.base_operations import BaseServerOperations
from flext_ldap.servers.factory import ServerOperationsFactory
from flext_ldap.servers.openldap1_operations import OpenLDAP1Operations
from flext_ldap.servers.openldap2_operations import OpenLDAP2Operations
from flext_ldap.servers.oid_operations import OracleOIDOperations
from flext_ldap.servers.oud_operations import OracleOUDOperations

# Stubs
from flext_ldap.servers.ad_operations import ActiveDirectoryOperations
from flext_ldap.servers.generic_operations import GenericServerOperations

__all__ = [
    "BaseServerOperations",
    "ServerOperationsFactory",
    "OpenLDAP1Operations",
    "OpenLDAP2Operations",
    "OracleOIDOperations",
    "OracleOUDOperations",
    "ActiveDirectoryOperations",
    "GenericServerOperations",
]

"""LDAP Advanced Controls Module.

This module provides advanced LDAP control implementations following
perl-ldap patterns with enterprise-grade functionality for specialized
LDAP operations and vendor-specific requirements.

Advanced controls include assertion controls, sync controls, tree operations,
and specialized directory management features essential for enterprise
deployments and sophisticated directory operations.

Architecture:
    - Assertion Controls: Conditional operation execution
    - Sync Controls: Content synchronization and replication
    - Management Controls: Directory structure management
    - Vendor Controls: Implementation-specific functionality

Usage Example:
    >>> from flext_ldap.controls.advanced import AssertionControl
    >>>
    >>> # Conditional operation with assertion
    >>> assertion_control = AssertionControl("(objectClass=person)")
    >>>
    >>> results = connection.modify(
    ...     "uid=john,ou=users,dc=example,dc=com",
    ...     changes={"mail": "john.new@example.com"},
    ...     controls=[assertion_control]
    ... )
    >>> # Modification only proceeds if assertion is true

References:
    - perl-ldap: lib/Net/LDAP/Control/*.pm (advanced controls)
    - RFC 4528: LDAP Assertion Control
    - RFC 4533: LDAP Content Synchronization Operation
    - RFC 3672: Subentries in LDAP
"""

from typing import TYPE_CHECKING

# Import advanced control components
from flext_ldapvanced.assertion import AssertionControl
from flext_ldapvanced.manage_dsa_it import ManageDsaITControl
from flext_ldapvanced.matched_values import MatchedValuesControl
from flext_ldapvanced.subentries import SubentriesControl
from flext_ldapvanced.sync_done import SyncDoneControl
from flext_ldapvanced.sync_request import SyncRequestControl
from flext_ldapvanced.sync_state import SyncStateControl
from flext_ldapvanced.tree_delete import TreeDeleteControl

__all__ = [
    # Core advanced controls
    "AssertionControl",
    "ManageDsaITControl",
    "MatchedValuesControl",
    "SubentriesControl",
    "SyncDoneControl",
    # Sync controls
    "SyncRequestControl",
    "SyncStateControl",
    # Management controls
    "TreeDeleteControl",
]

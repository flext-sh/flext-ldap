"""LDAP Transaction Support Module.

This module provides comprehensive LDAP transaction functionality following
enterprise-grade patterns with atomic operations, commit/rollback capabilities,
and comprehensive error handling.

Transaction support enables grouping multiple LDAP operations into atomic
units that either all succeed or all fail, essential for data consistency
and enterprise reliability requirements.

Architecture:
    - TransactionManager: Main transaction coordination and management
    - LDAPTransaction: Individual transaction context and operations
    - TransactionControl: LDAP control for transaction operations
    - TransactionIsolation: Isolation level management and conflict detection

Usage Example:
    >>> from ldap_core_shared.transactions import TransactionManager
    >>>
    >>> # Atomic multi-operation transaction
    >>> tx_manager = TransactionManager(connection)
    >>> async with tx_manager.begin_transaction() as tx:
    ...     await tx.add_entry("uid=user1,ou=users,dc=example,dc=com", user_attrs)
    ...     await tx.modify_entry("cn=group1,ou=groups,dc=example,dc=com", group_changes)
    ...     await tx.delete_entry("uid=olduser,ou=users,dc=example,dc=com")
    ...     # Automatically commits on success, rolls back on exception

References:
    - RFC 5805: LDAP Transactions
    - perl-ldap: Transaction patterns and error handling
    - Enterprise transaction processing patterns

"""

from typing import TYPE_CHECKING

from ldap_core_shared.transactions.controls import TransactionSpecificationControl

# Import transaction components
from ldap_core_shared.transactions.manager import LDAPTransaction, TransactionManager

__all__ = [
    # Core transaction management
    "LDAPTransaction",
    "TransactionManager",
    "TransactionSpecificationControl",
]

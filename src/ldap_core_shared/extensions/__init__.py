"""LDAP Extensions Module.

This module provides comprehensive LDAP extension implementations following RFC standards.
Based on perl-ldap Net::LDAP::Extension functionality, providing enterprise-grade
extension management for LDAP operations.

Extensions are special LDAP operations that extend the protocol beyond the basic
operations (bind, search, modify, add, delete, compare, abandon). They enable
advanced features like password modification, identity discovery, and connection
security upgrades.

Example:
    >>> from ldap_core_shared.extensions import WhoAmIExtension
    >>> whoami = WhoAmIExtension()
    >>> result = connection.extended_operation(whoami)
    >>> print(f"Current identity: {result.authorization_identity}")

References:
    - perl-ldap: lib/Net/LDAP/Extension/
    - RFC 4511: Section 4.12 - Extended Operation
    - RFC 4532: LDAP "Who am I?" Operation
    - RFC 3062: LDAP Password Modify Extended Operation
"""

from typing import TYPE_CHECKING

from ldap_core_shared.extensions.base import LDAPExtension
from ldap_core_shared.extensions.cancel import CancelExtension
from ldap_core_shared.extensions.modify_password import ModifyPasswordExtension
from ldap_core_shared.extensions.start_tls import StartTLSExtension
from ldap_core_shared.extensions.who_am_i import WhoAmIExtension

__all__ = [
    "LDAPExtension",
    "WhoAmIExtension",
    "ModifyPasswordExtension",
    "StartTLSExtension",
    "CancelExtension",
]

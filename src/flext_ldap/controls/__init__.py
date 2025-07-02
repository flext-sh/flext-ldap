"""LDAP Controls Module.

This module provides comprehensive LDAP control implementations following RFC standards.
Based on perl-ldap Net::LDAP::Control functionality, providing enterprise-grade
control management for LDAP operations.

Controls are extensions to the LDAP protocol that provide additional functionality
such as paging, sorting, virtual list views, and security features.

Example:
    >>> from flext_ldapport PagedResultsControl
    >>> paged_control = PagedResultsControl(page_size=DEFAULT_LARGE_LIMIT)
    >>> search_results = connection.search(
    ...     base_dn="dc=example,dc=com",
    ...     filter_expr="(objectClass=person)",
    ...     controls=[paged_control],
    ... )

References:
    - perl-ldap: lib/Net/LDAP/Control/
    - RFC 2696: LDAP Control Extension for Simple Paged Results Manipulation
    - RFC 2891: LDAP Control Extension for Server Side Sorting of Search Results
    - RFC 4370: Lightweight Directory Access Protocol (LDAP) Proxied
      Authorization Control
"""

from typing import TYPE_CHECKING

from flext_ldaperead import PreReadControl
from flext_ldapoxy_auth import ProxyAuthorizationControl
from flext_ldaprsistent_search import PersistentSearchControl
from flext_ldaprt import ServerSideSortControl
from flext_ldapse import LDAPControl
from flext_ldapssword_policy import PasswordPolicyControl
from flext_ldapstread import PostReadControl

from flext_ldap.domain.results import Result
from flext_ldap.utils.constants import DEFAULT_LARGE_LIMIT

__all__ = [
    "LDAPControl",
    "PagedResultsControl",
    "PagedSearchIterator",
    "PasswordPolicyControl",
    "PersistentSearchControl",
    "PostReadControl",
    "PreReadControl",
    "ProxyAuthorizationControl",
    "ServerSideSortControl",
]

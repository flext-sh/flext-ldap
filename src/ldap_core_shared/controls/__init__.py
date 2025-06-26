from ldap_core_shared.utils.constants import DEFAULT_LARGE_LIMIT

"""LDAP Controls Module.

# Constants for magic values

This module provides comprehensive LDAP control implementations following RFC standards.
Based on perl-ldap Net::LDAP::Control functionality, providing enterprise-grade
control management for LDAP operations.

Controls are extensions to the LDAP protocol that provide additional functionality
such as paging, sorting, virtual list views, and security features.

Example:
    >>> from ldap_core_shared.controls import PagedResultsControl
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

from ldap_core_shared.controls.base import LDAPControl
from ldap_core_shared.controls.paged import PagedResultsControl, PagedSearchIterator
from ldap_core_shared.controls.password_policy import PasswordPolicyControl
from ldap_core_shared.controls.persistent_search import PersistentSearchControl
from ldap_core_shared.controls.postread import PostReadControl
from ldap_core_shared.controls.preread import PreReadControl
from ldap_core_shared.controls.proxy_auth import ProxyAuthorizationControl
from ldap_core_shared.controls.sort import ServerSideSortControl

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

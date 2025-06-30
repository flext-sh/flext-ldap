"""LDAP Advanced Utilities Module - Enterprise Utility Infrastructure.

This module provides comprehensive enterprise-grade utility functions following
perl-ldap patterns with enhanced URL parsing, time management, filter processing,
and directory operation helpers for the LDAP Core Shared library.

DESIGN PATTERN: ENTERPRISE UTILITY INFRASTRUCTURE (COMPREHENSIVE SUPPORT)
========================================================================

This implementation provides enterprise-grade utility components:
- URL: LDAP URL parsing, validation, and manipulation (RFC 4516 compliant)
- Time: Generalized time processing and conversion utilities (RFC 4517 compliant)
- Filter: LDAP filter parsing, validation, and transformation (RFC 4515 compliant)
- DN: Distinguished name parsing and manipulation (RFC 4514 compliant)
- Entry: Entry processing and attribute management (RFC 4511 compliant)
- Pattern-based validation and normalization across all utility types
- Enterprise integration support for complex directory scenarios

UTILITY COMPONENTS ARCHITECTURE:
===============================
- LDAPUrl: Complete URL processing with validation and normalization
- GeneralizedTime: LDAP time format handling with timezone support
- DistinguishedName: DN parsing, validation, and manipulation
- LDAPFilter: Filter parsing, optimization, and validation
- EntryProcessor: Entry attribute processing and normalization
- DNParser/DNValidator: Specialized DN handling components
- FilterParser: Advanced filter parsing and transformation

Usage Example:
    >>> from flext_ldap.utilities import LDAPUrl, LDAPFilter, GeneralizedTime
    >>> from flext_ldapmport DistinguishedName, EntryProcessor
    >>>
    >>> # Parse and manipulate LDAP URLs (RFC 4516)
    >>> url = LDAPUrl("ldap://server.example.com:389/ou=users,dc=example,dc=com??sub?(cn=john)")
    >>> print(f"Host: {url.hostname}, Base: {url.base_dn}, Scope: {url.scope}")
    >>>
    >>> # Process LDAP filters with optimization (RFC 4515)
    >>> filter_obj = LDAPFilter("(&(objectClass=person)(cn=john*))")
    >>> if filter_obj.is_valid():
    ...     optimized = filter_obj.optimize()
    ...     print(f"Optimized filter: {optimized}")
    >>>
    >>> # Handle generalized time with timezone support (RFC 4517)
    >>> gt = GeneralizedTime.now()
    >>> ldap_time_str = gt.to_ldap_string()
    >>> parsed_time = GeneralizedTime.from_ldap_string(ldap_time_str)
    >>>
    >>> # Distinguished name processing (RFC 4514)
    >>> dn = DistinguishedName("cn=John Doe,ou=Users,dc=example,dc=com")
    >>> normalized = dn.normalize()
    >>> parent_dn = dn.parent()
    >>>
    >>> # Entry processing and validation
    >>> processor = EntryProcessor()
    >>> processed_entry = processor.normalize_entry(entry_data)

References:
    - /home/marlonsc/CLAUDE.md → Universal principles (UTILITY PATTERNS)
    - ../CLAUDE.md → PyAuto workspace patterns (ENTERPRISE UTILITIES)
    - ./CLAUDE.local.md → Project-specific utility requirements
    - RFC 4511: LDAP Protocol Specification (core protocol)
    - RFC 4514: LDAP String Representation of Distinguished Names
    - RFC 4515: LDAP String Representation of Search Filters
    - RFC 4516: LDAP Uniform Resource Locator
    - RFC 4517: LDAP Syntaxes and Matching Rules
    - perl-ldap: lib/Net/LDAP/Util.pm (reference implementation)
"""

from typing import TYPE_CHECKING

from flext_ldapilter import FilterParser, LDAPFilter
from flext_ldapime import GeneralizedTime, LDAPTimeUtils
from flext_ldapn import DistinguishedName, DNParser, DNValidator
from flext_ldapntry import EntryProcessor, LDAPEntry

# Import utility components
from flext_ldaprl import LDAPUrl, parse_ldap_url

__all__ = [
    "DNParser",
    "DNValidator",
    # DN utilities
    "DistinguishedName",
    "EntryProcessor",
    "FilterParser",
    # Time utilities
    "GeneralizedTime",
    # Entry utilities
    "LDAPEntry",
    # Filter utilities
    "LDAPFilter",
    "LDAPTimeUtils",
    # URL utilities
    "LDAPUrl",
    "parse_ldap_url",
]

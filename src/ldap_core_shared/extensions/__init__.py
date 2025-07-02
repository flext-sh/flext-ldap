"""LDAP Extensions Module.

This module provides comprehensive LDAP extension implementations following
RFC standards and vendor-specific extensions.
Based on perl-ldap Net::LDAP::Extension functionality, providing enterprise-grade
extension management for LDAP operations.

Extensions include:
    - Standard RFC extensions (Who Am I, Password Modify, Start TLS, Cancel)
    - Vendor-specific extensions (Microsoft AD, OpenLDAP, IBM, Novell, Oracle)

Extensions are special LDAP operations that extend the protocol beyond the basic
operations (bind, search, modify, add, delete, compare, abandon). They enable
advanced features like password modification, identity discovery, connection
security upgrades, and vendor-specific functionality.

Example:
    >>> from ldap_core_shared.extensions import WhoAmIExtension
    >>> from ldap_core_shared.extensions.microsoft import ActiveDirectoryExtensions
    >>>
    >>> # Standard extension
    >>> whoami = WhoAmIExtension()
    >>> result = connection.extended_operation(whoami)
    >>> print(f"Current identity: {result.authorization_identity}")
    >>>
    >>> # Vendor-specific extension
    >>> ad_ext = ActiveDirectoryExtensions()
    >>> paged_control = ad_ext.create_paged_search_control(page_size=1000)

References:
    - perl-ldap: lib/Net/LDAP/Extension/
    - RFC 4511: Section 4.12 - Extended Operation
    - RFC 4532: LDAP "Who am I?" Operation
    - RFC 3062: LDAP Password Modify Extended Operation
    - Vendor-specific LDAP documentation

"""

from typing import TYPE_CHECKING

# Standard LDAP extensions
from ldap_core_shared.extensions.base import LDAPExtension
from ldap_core_shared.extensions.cancel import CancelExtension
from ldap_core_shared.extensions.ibm import IBMControls, IBMExtensions

# Vendor-specific extensions
from ldap_core_shared.extensions.microsoft import (
    ActiveDirectoryExtensions,
    MSADControls,
)
from ldap_core_shared.extensions.modify_password import ModifyPasswordExtension
from ldap_core_shared.extensions.novell import NovellControls, NovellExtensions
from ldap_core_shared.extensions.openldap import OpenLDAPControls, OpenLDAPExtensions
from ldap_core_shared.extensions.oracle import OracleControls, OracleExtensions
from ldap_core_shared.extensions.start_tls import StartTLSExtension
from ldap_core_shared.extensions.who_am_i import WhoAmIExtension

__all__ = [
    # Vendor-specific extensions
    "ActiveDirectoryExtensions",
    # Standard LDAP extensions
    "CancelExtension",
    "IBMControls",
    "IBMExtensions",
    "LDAPExtension",
    "MSADControls",
    "ModifyPasswordExtension",
    "NovellControls",
    "NovellExtensions",
    "OpenLDAPControls",
    "OpenLDAPExtensions",
    "OracleControls",
    "OracleExtensions",
    "StartTLSExtension",
    "WhoAmIExtension",
]

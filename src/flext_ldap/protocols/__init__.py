"""LDAP Protocol Support Module.

This module provides comprehensive LDAP protocol implementations following
perl-ldap patterns with support for LDAPI (Unix domain sockets), LDAPS (SSL/TLS),
and DSML (Directory Services Markup Language) protocols.

Protocol implementations include:
    - LDAPI: Unix domain socket protocol for local connections
    - LDAPS: SSL/TLS encrypted LDAP protocol for secure connections
    - DSML: XML-based directory services protocol for web integration
    - Extended protocol features and negotiation capabilities

These protocols enable diverse connection methods for enterprise deployments,
security requirements, and web service integration scenarios.

Usage Example:
    >>> from flext_ldap.protocols import LDAPIConnection, LDAPSConnection
    >>>
    >>> # Unix domain socket connection
    >>> ldapi_conn = LDAPIConnection("/var/run/ldapi")
    >>> await ldapi_conn.connect()
    >>>
    >>> # SSL/TLS encrypted connection
    >>> ldaps_conn = LDAPSConnection(
    ...     "ldaps://secure.example.com:636",
    ...     ssl_context=ssl_context
    ... )
    >>> await ldaps_conn.connect()

References:
    - perl-ldap: lib/Net/LDAP.pm (protocol support)
    - RFC 4511: LDAP Protocol Specification
    - RFC 2830: LDAP Extension for Transport Layer Security
    - RFC 3296: Named Subordinate References in LDAP
    - DSML v2: Directory Services Markup Language

"""

from typing import TYPE_CHECKING

from flext_ldap.connections.base import Connection

# Import protocol implementations

__all__ = [
    "DSMLConnection",
    # DSML protocol
    "DSMLProtocol",
    # LDAPI protocol
    "LDAPIConnection",
    "LDAPIProtocol",
    # LDAPS protocol
    "LDAPSConnection",
    "LDAPSProtocol",
]

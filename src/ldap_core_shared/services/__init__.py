"""LDAP Directory Services Module.

This module provides comprehensive directory services functionality following
perl-ldap Net::LDAP server discovery and schema management patterns with
enterprise-grade Python enhancements.

Directory services enable automatic discovery of server capabilities, schema
information, and feature detection for intelligent LDAP client behavior.

Architecture:
    - RootDSEService: Server capability discovery and configuration
    - SchemaService: LDAP schema management and validation
    - CapabilityDetection: Feature detection and compatibility checking
    - ServerInfo: Comprehensive server information aggregation

Usage Example:
    >>> from ldap_core_shared.services import RootDSEService
    >>>
    >>> # Discover server capabilities
    >>> rootdse = RootDSEService(connection)
    >>> info = await rootdse.discover_capabilities()
    >>> print(f"Supported extensions: {info.supported_extensions}")
    >>> print(f"LDAP version: {info.ldap_version}")
    >>>
    >>> # Check specific features
    >>> if rootdse.supports_extension("1.3.6.1.4.1.4203.1.11.3"):
    ...     print("Server supports WhoAmI extension")

References:
    - perl-ldap: lib/Net/LDAP/RootDSE.pm
    - perl-ldap: lib/Net/LDAP/Schema.pm
    - RFC 4512: Lightweight Directory Access Protocol (LDAP): Directory Information Models
    - RFC 4513: LDAP Authentication Methods and Security Mechanisms
"""

from typing import TYPE_CHECKING

from ldap_core_shared.services.capabilities import CapabilityDetection, FeatureMatrix

# Import core directory services
from ldap_core_shared.services.rootdse import RootDSEService, ServerInfo
from ldap_core_shared.services.schema import LDAPSchema, SchemaService

__all__ = [
    # Capability detection
    "CapabilityDetection",
    "FeatureMatrix",
    "LDAPSchema",
    # Root DSE and server discovery
    "RootDSEService",
    # Schema management
    "SchemaService",
    "ServerInfo",
]

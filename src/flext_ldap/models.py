"""LDAP Models - Single FlextLDAPModels class following FLEXT patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextModels

from flext_ldap.connection_config import FlextLDAPConnectionConfig
from flext_ldap.constants import FlextLDAPConstants
from flext_ldap.entities import FlextLDAPEntities
from flext_ldap.fields import FlextLDAPFields
from flext_ldap.settings import FlextLDAPSettings
from flext_ldap.typings import (
    LdapAttributeDict,
    LdapAttributeValue,
    LdapSearchResult,
)
from flext_ldap.value_objects import FlextLDAPValueObjects

# =============================================================================
# SINGLE FLEXT LDAP MODELS CLASS - Inheriting from FlextModels
# =============================================================================


class FlextLDAPModels(FlextModels.AggregateRoot):
    """Single FlextLDAPModels class inheriting from FlextModels.

    Consolidates ALL LDAP models into a single class following FLEXT patterns.
    Everything from the previous model definitions is now available as
    internal classes with full backward compatibility.

    """

    # =========================================================================
    # CONFIGURATION MODELS - LDAP Configuration Classes
    # =========================================================================

    class Configuration:
        """LDAP configuration models extending FlextModels."""

        # Configuration model aliases
        Settings = FlextLDAPSettings
        ConnectionConfig = FlextLDAPConnectionConfig

        # Factory methods
        @staticmethod
        def create_development() -> FlextLDAPSettings:
            """Create development configuration.

            Returns:
                FlextLDAPSettings: Development configuration settings.

            """
            return FlextLDAPSettings.create_development()

        @staticmethod
        def create_production() -> FlextLDAPSettings:
            """Create production configuration.

            Returns:
                FlextLDAPSettings: Production configuration settings.

            """
            return FlextLDAPSettings.create_production()

        @staticmethod
        def create_test() -> FlextLDAPSettings:
            """Create test configuration.

            Returns:
                FlextLDAPSettings: Test configuration settings.

            """
            return FlextLDAPSettings.create_test()

    # =========================================================================
    # DOMAIN MODELS - LDAP Domain Entities
    # =========================================================================

    class Domain:
        """LDAP domain models extending FlextModels."""

        # Domain entity aliases
        User = FlextLDAPEntities.User
        Group = FlextLDAPEntities.Group
        Entry = FlextLDAPEntities.Entry

        # Value object aliases
        DistinguishedName = FlextLDAPValueObjects.DistinguishedName
        Filter = FlextLDAPValueObjects.Filter
        Scope = FlextLDAPValueObjects.Scope

    # =========================================================================
    # REQUEST MODELS - LDAP Operation Requests
    # =========================================================================

    class Request:
        """LDAP request models for operations."""

        # Request model aliases
        SearchRequest = FlextLDAPEntities.SearchRequest
        CreateUserRequest = FlextLDAPEntities.CreateUserRequest

    # =========================================================================
    # RESPONSE MODELS - LDAP Operation Responses
    # =========================================================================

    class Response:
        """LDAP response models for operations."""

        # Response model aliases
        SearchResponse = FlextLDAPEntities.SearchResponse

    # =========================================================================
    # FIELD MODELS - LDAP Field Definitions and Processors
    # =========================================================================

    class Field:
        """LDAP field definitions and processors."""

        # Field definition aliases
        DataType = FlextLDAPFields.DataTypes
        ScopeEnum = FlextLDAPFields.Scopes

        # Processor aliases
        AttributeProcessor = FlextLDAPFields.Processors
        DomainValidator = FlextLDAPFields.Validators

    # =========================================================================
    # TYPE MODELS - LDAP Type Definitions
    # =========================================================================

    class Type:
        """LDAP type definitions."""

        # Type aliases
        AttributeDict = LdapAttributeDict
        AttributeValue = LdapAttributeValue
        SearchResult = LdapSearchResult

    # =========================================================================
    # CONSTANT MODELS - LDAP Constants Access
    # =========================================================================

    class Constant:
        """LDAP constants access - use FlextLDAPConstants directly."""

        # Direct reference to unified constants class
        All = FlextLDAPConstants
        Protocol = FlextLDAPConstants.Protocol
        Connection = FlextLDAPConstants.Connection
        Attribute = FlextLDAPConstants.Attributes


# =============================================================================
# LEGACY MODEL ALIASES - Backward Compatibility
# =============================================================================

# All legacy aliases are provided through the imports above - no need for
# self-assignments as ruff correctly identifies them as redundant

# Entity status - using string literal following flext-core patterns
FlextLDAPEntityStatus = "active"  # Default status for LDAP entities


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Main class following flext-core pattern
    "FlextLDAPModels",
]

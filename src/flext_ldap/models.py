"""LDAP Models - Single FlextLDAPModels class following FLEXT patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import final

from flext_core import FlextModels, FlextResult

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

# Python 3.13 type aliases for LDAP models
type LdapSettingsType = FlextLDAPSettings
type LdapConnectionConfigType = FlextLDAPConnectionConfig
type LdapUserType = FlextLDAPEntities.User
type LdapGroupType = FlextLDAPEntities.Group

# =============================================================================
# SINGLE FLEXT LDAP MODELS CLASS - Inheriting from FlextModels
# =============================================================================


@final
class FlextLDAPModels(FlextModels.AggregateRoot):
    """Single FlextLDAPModels class inheriting from FlextModels.

    Consolidates ALL LDAP models into a single class following FLEXT patterns.
    Everything from the previous model definitions is now available as
    internal classes with full backward compatibility.

    Uses Python 3.13 final decorator and type aliases for enhanced type safety.
    """

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate business rules for LDAP models aggregate.

        Models aggregate always passes validation as it contains only aliases
        to other validated domain entities.

        Returns:
            FlextResult[None]: Always successful validation.

        """
        return FlextResult.ok(None)

    # =========================================================================
    # CONFIGURATION MODELS - LDAP Configuration Classes
    # =========================================================================

    @final
    class Configuration:
        """LDAP configuration models extending FlextModels."""

        # Configuration model aliases using Python 3.13 type patterns
        Settings: type[FlextLDAPSettings] = FlextLDAPSettings
        ConnectionConfig: type[FlextLDAPConnectionConfig] = FlextLDAPConnectionConfig

        # Factory methods with Python 3.13 return type annotations
        @staticmethod
        def create_development() -> LdapSettingsType:
            """Create development configuration using SOURCE OF TRUTH patterns."""
            return FlextLDAPSettings.create_development()

        @staticmethod
        def create_production() -> LdapSettingsType:
            """Create production configuration using SOURCE OF TRUTH patterns."""
            return FlextLDAPSettings.create_production()

        @staticmethod
        def create_test() -> LdapSettingsType:
            """Create test configuration using SOURCE OF TRUTH patterns."""
            return FlextLDAPSettings.create_test()

    # =========================================================================
    # DOMAIN MODELS - LDAP Domain Entities
    # =========================================================================

    @final
    class Domain:
        """LDAP domain models extending FlextModels."""

        # Domain entity aliases using Python 3.13 type patterns
        User: type[FlextLDAPEntities.User] = FlextLDAPEntities.User
        Group: type[FlextLDAPEntities.Group] = FlextLDAPEntities.Group
        Entry: type[FlextLDAPEntities.Entry] = FlextLDAPEntities.Entry

        # Value object aliases using Python 3.13 type patterns
        DistinguishedName: type[FlextLDAPValueObjects.DistinguishedName] = (
            FlextLDAPValueObjects.DistinguishedName
        )
        Filter: type[FlextLDAPValueObjects.Filter] = FlextLDAPValueObjects.Filter
        Scope: type[FlextLDAPValueObjects.Scope] = FlextLDAPValueObjects.Scope

    # =========================================================================
    # REQUEST MODELS - LDAP Operation Requests
    # =========================================================================

    @final
    class Request:
        """LDAP request models for operations."""

        # Request model aliases using Python 3.13 type patterns
        SearchRequest: type[FlextLDAPEntities.SearchRequest] = (
            FlextLDAPEntities.SearchRequest
        )
        CreateUserRequest: type[FlextLDAPEntities.CreateUserRequest] = (
            FlextLDAPEntities.CreateUserRequest
        )

    # =========================================================================
    # RESPONSE MODELS - LDAP Operation Responses
    # =========================================================================

    @final
    class Response:
        """LDAP response models for operations."""

        # Response model aliases using Python 3.13 type patterns
        SearchResponse: type[FlextLDAPEntities.SearchResponse] = (
            FlextLDAPEntities.SearchResponse
        )

    # =========================================================================
    # FIELD MODELS - LDAP Field Definitions and Processors
    # =========================================================================

    @final
    class Field:
        """LDAP field definitions and processors."""

        # Field definition aliases using SOURCE OF TRUTH
        DataType = FlextLDAPFields.DataTypes
        ScopeEnum = FlextLDAPFields.Scopes

        # Processor aliases using SOURCE OF TRUTH
        AttributeProcessor = FlextLDAPFields.Processors
        DomainValidator = FlextLDAPFields.Validators

    # =========================================================================
    # TYPE MODELS - LDAP Type Definitions
    # =========================================================================

    @final
    class Type:
        """LDAP type definitions using Python 3.13 type aliases."""

        # Type aliases using Python 3.13 patterns
        AttributeDict = LdapAttributeDict
        AttributeValue = LdapAttributeValue
        SearchResult = LdapSearchResult

    # =========================================================================
    # CONSTANT MODELS - LDAP Constants Access
    # =========================================================================

    @final
    class Constant:
        """LDAP constants access using SOURCE OF TRUTH - FlextLDAPConstants only."""

        # Direct reference to unified constants class - SOURCE OF TRUTH
        All = FlextLDAPConstants
        Protocol = FlextLDAPConstants.Protocol
        Connection = FlextLDAPConstants.Connection
        Attribute = FlextLDAPConstants.Attributes
        Validation = FlextLDAPConstants.LdapValidation
        Scope = FlextLDAPConstants.Scopes


# =============================================================================
# LEGACY MODEL ALIASES - Backward Compatibility
# =============================================================================

# All legacy aliases are provided through the imports above - no need for
# self-assignments as ruff correctly identifies them as redundant

# Python 3.13 type alias for entity status using SOURCE OF TRUTH
type FlextLDAPEntityStatus = str

# Default status from SOURCE OF TRUTH patterns
DEFAULT_LDAP_ENTITY_STATUS: FlextLDAPEntityStatus = (
    FlextLDAPConstants.DefaultValues.STRING_FIELD_TYPE
)


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Main class following flext-core pattern
    "FlextLDAPModels",
]

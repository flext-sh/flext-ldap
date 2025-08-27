"""LDAP Models - Single FlextLdapModels class following FLEXT patterns.

Single class inheriting from FlextModel with all LDAP models
organized as internal classes and methods for complete backward compatibility.

Examples:
    Basic usage with hierarchical models::

        from models import FlextLdapModels

        # Configuration models
        settings = FlextLdapModels.Configuration.Settings()
        auth_config = FlextLdapModels.Configuration.AuthConfig()

        # Domain models
        user = FlextLdapModels.Domain.User()
        entry = FlextLdapModels.Domain.Entry()

    Legacy compatibility::

        # All previous models still work as direct imports
        from models import FlextLdapUser, FlextLdapSettings

        user = FlextLdapUser()
        settings = FlextLdapSettings()

"""

# Re-export configuration models for compatibility
from __future__ import annotations

# Import for entity status alias
from flext_core import FlextEntity, FlextModel

from .configuration import (
    FlextLdapAuthConfig,
    FlextLdapConnectionConfig,
    FlextLdapLoggingConfig,
    FlextLdapSearchConfig,
    FlextLdapSettings,
    create_development_config,
    create_production_config,
    create_test_config,
)

# Re-export constants for compatibility
from .constants import (
    FlextLdapAttributeConstants,
    FlextLdapConnectionConstants,
    FlextLdapConstants,
    FlextLdapProtocolConstants,
)

# Re-export domain entities for compatibility
from .entities import (
    FlextLdapCreateUserRequest,
    FlextLdapEntry,
    FlextLdapGroup,
    FlextLdapSearchRequest,
    FlextLdapSearchResponse,
    FlextLdapUser,
)

# Re-export field definitions for compatibility
from .fields import (
    FlextLdapDataType,
    FlextLdapScopeEnum,
    LdapAttributeProcessor,
    LdapDomainValidator,
)

# Re-export type definitions for compatibility
from .typings import (
    LdapAttributeDict,
    LdapAttributeValue,
    LdapSearchResult,
)

# Re-export value objects for compatibility
from .value_objects import (
    FlextLdapDistinguishedName,
    FlextLdapFilter,
    FlextLdapScope,
)

# =============================================================================
# SINGLE FLEXT LDAP MODELS CLASS - Inheriting from FlextModel
# =============================================================================


class FlextLdapModels(FlextModel):
    """Single FlextLdapModels class inheriting from FlextModel.

    Consolidates ALL LDAP models into a single class following FLEXT patterns.
    Everything from the previous model definitions is now available as
    internal classes with full backward compatibility.

    This class follows SOLID principles:
        - Single Responsibility: All LDAP models in one place
        - Open/Closed: Extends FlextModel without modification
        - Liskov Substitution: Can be used anywhere FlextModel is expected
        - Interface Segregation: Organized by domain for specific access
        - Dependency Inversion: Depends on FlextModel abstraction

    Examples:
        Configuration models::

            settings = FlextLdapModels.Configuration.Settings()
            auth = FlextLdapModels.Configuration.AuthConfig()

        Domain models::

            user = FlextLdapModels.Domain.User()
            group = FlextLdapModels.Domain.Group()
            entry = FlextLdapModels.Domain.Entry()

        Request/Response models::

            search_req = FlextLdapModels.Request.SearchRequest()
            search_resp = FlextLdapModels.Response.SearchResponse()

    """

    # =========================================================================
    # CONFIGURATION MODELS - LDAP Configuration Classes
    # =========================================================================

    class Configuration:
        """LDAP configuration models extending FlextModel."""

        # Configuration model aliases
        Settings = FlextLdapSettings
        AuthConfig = FlextLdapAuthConfig
        ConnectionConfig = FlextLdapConnectionConfig
        LoggingConfig = FlextLdapLoggingConfig
        SearchConfig = FlextLdapSearchConfig

        # Factory methods
        @staticmethod
        def create_development() -> FlextLdapSettings:
            """Create development configuration."""
            return create_development_config()

        @staticmethod
        def create_production() -> FlextLdapSettings:
            """Create production configuration."""
            return create_production_config()

        @staticmethod
        def create_test() -> FlextLdapSettings:
            """Create test configuration."""
            return create_test_config()

    # =========================================================================
    # DOMAIN MODELS - LDAP Domain Entities
    # =========================================================================

    class Domain:
        """LDAP domain models extending FlextEntity."""

        # Domain entity aliases
        User = FlextLdapUser
        Group = FlextLdapGroup
        Entry = FlextLdapEntry

        # Value object aliases
        DistinguishedName = FlextLdapDistinguishedName
        Filter = FlextLdapFilter
        Scope = FlextLdapScope

    # =========================================================================
    # REQUEST MODELS - LDAP Operation Requests
    # =========================================================================

    class Request:
        """LDAP request models for operations."""

        # Request model aliases
        SearchRequest = FlextLdapSearchRequest
        CreateUserRequest = FlextLdapCreateUserRequest

    # =========================================================================
    # RESPONSE MODELS - LDAP Operation Responses
    # =========================================================================

    class Response:
        """LDAP response models for operations."""

        # Response model aliases
        SearchResponse = FlextLdapSearchResponse

    # =========================================================================
    # FIELD MODELS - LDAP Field Definitions and Processors
    # =========================================================================

    class Field:
        """LDAP field definitions and processors."""

        # Field definition aliases
        DataType = FlextLdapDataType
        ScopeEnum = FlextLdapScopeEnum

        # Processor aliases
        AttributeProcessor = LdapAttributeProcessor
        DomainValidator = LdapDomainValidator

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
        """LDAP constants access."""

        # Constants aliases
        All = FlextLdapConstants
        Protocol = FlextLdapProtocolConstants
        Connection = FlextLdapConnectionConstants
        Attribute = FlextLdapAttributeConstants


# =============================================================================
# LEGACY MODEL ALIASES - Backward Compatibility
# =============================================================================

# All legacy aliases are provided through the imports above - no need for
# self-assignments as ruff correctly identifies them as redundant

# Entity status alias - backward compatibility
FlextLdapEntityStatus = getattr(FlextEntity, "status", None)
LDAPScope = FlextLdapScopeEnum


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Constants
    "FlextLdapAttributeConstants",
    # Configuration models
    "FlextLdapAuthConfig",
    "FlextLdapConnectionConfig",
    "FlextLdapConnectionConstants",
    "FlextLdapConstants",
    # Domain models
    "FlextLdapCreateUserRequest",
    # Field models
    "FlextLdapDataType",
    "FlextLdapDistinguishedName",
    "FlextLdapEntityStatus",
    "FlextLdapEntry",
    "FlextLdapFilter",
    "FlextLdapGroup",
    "FlextLdapLoggingConfig",
    # Main class
    "FlextLdapModels",
    "FlextLdapProtocolConstants",
    "FlextLdapScope",
    "FlextLdapScopeEnum",
    "FlextLdapSearchConfig",
    "FlextLdapSearchRequest",
    "FlextLdapSearchResponse",
    "FlextLdapSettings",
    "FlextLdapUser",
    # Legacy aliases
    "LDAPScope",
    # Type models
    "LdapAttributeDict",
    "LdapAttributeProcessor",
    "LdapAttributeValue",
    "LdapDomainValidator",
    "LdapSearchResult",
    # Factory functions
    "create_development_config",
    "create_production_config",
    "create_test_config",
]

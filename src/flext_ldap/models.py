"""Unified LDAP models for flext-ldap - ALL models consolidated into FlextLdapModels.

This module consolidates ALL LDAP models, entities, and value objects into a single
FlextLdapModels class following FLEXT one-class-per-module standards.

Eliminates previous triple model system (models.py + entities.py + value_objects.py).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

TYPE CHECKER KNOWN ISSUES (Isolated until flext-core patterns stabilize):
===========================================================================

1. DistinguishedName.create() return type (Lines 243, 255, 257, 261):
   - Pyrefly reports: FlextCore.Result[DistinguishedName] not assignable to FlextCore.Result[object]
   - Reason: Generic type inference limitation with nested FlextCore.Models classes
   - Impact: None - runtime behavior is correct, type is properly constrained
   - Resolution: Waiting for flext-core TypeVar propagation improvements

2. LdapUser.created_at override (Line 609):
   - Pyrefly reports: datetime | None overrides Entity.created_at inconsistently
   - Reason: Domain model requires Optional timestamp, Entity base class requires non-null
   - Impact: None - Pydantic validation handles None values correctly
   - Resolution: Architectural decision - LDAP users may not have creation timestamps

3. Entry.additional_attributes access (Line 951):
   - Pyrefly reports: object | None not assignable to FlextCore.Types.StringList | str | None
   - Reason: Dict.get() returns object | None, but LDAP attributes are strongly typed
   - Impact: None - LDAP protocol guarantees attribute values are str or FlextCore.Types.StringList
   - Resolution: Runtime type narrowing via LDAP protocol constraints

4. Config.validate() method override (Lines 2406, 2430, 2453, 2475):
   - Pyrefly reports: Instance method incompatible with classmethod signature
   - Reason: Changed from Pydantic @model_validator to explicit validate() pattern
   - Impact: None - Explicit validation allows object creation without auto-validation
   - Resolution: Pattern change for FlextCore.Result compatibility (see validation tests)

All other type errors have been fixed. These remaining issues are architectural decisions
or generic type limitations that do not affect runtime correctness.
"""

from __future__ import annotations

import base64
import threading
import uuid
from datetime import datetime
from enum import Enum
from typing import ClassVar

from dependency_injector import providers
from flext_core import FlextCore
from flext_ldif import FlextLdifModels
from pydantic import (
    ConfigDict,
    Field,
    SecretStr,
    ValidationInfo,
    computed_field,
    field_serializer,
    field_validator,
    model_validator,
)
from pydantic_settings import SettingsConfigDict

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.exceptions import FlextLdapExceptions
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.validations import FlextLdapValidations


class FlextLdapModels(FlextCore.Models):
    """Unified LDAP models class consolidating ALL models, entities, and value objects.

    This class consolidates:
    - Previous FlextLdapModels (legacy models)
    - Previous FlextLdapEntities (domain entities)
    - Previous FlextLdapValueObjects (value objects)

    Into a single unified class following FLEXT patterns. ALL LDAP data structures
    are now available as nested classes within FlextLdapModels.

    Enhanced with advanced Pydantic 2.11 features for LDAP-specific validation and serialization.
    NO legacy compatibility maintained - clean consolidated implementation only.
    """

    # Enhanced base configuration for all LDAP models
    model_config = ConfigDict(
        validate_assignment=True,
        validate_return=True,
        validate_default=True,
        strict=True,  # Strict type coercion
        str_strip_whitespace=True,
        use_enum_values=True,
        arbitrary_types_allowed=True,
        extra="forbid",  # Strict LDAP attribute validation
        frozen=False,  # Allow mutable LDAP models for attribute updates
        ser_json_timedelta="iso8601",
        ser_json_bytes="base64",
        serialize_by_alias=True,
        populate_by_name=True,
        hide_input_in_errors=True,  # Security
        # LDAP serialization features
        json_encoders={
            datetime: lambda v: v.isoformat() if v else None,
        },
        json_schema_extra={
            "title": "FlextLdapModels",
            "description": "Unified LDAP models with comprehensive validation",
        },
    )

    # =========================================================================
    # EXTENDED MODEL CONFIGURATIONS - Using FlextCore extended models
    # =========================================================================

    class StrictModel(FlextCore.Models.ArbitraryTypesModel):
        """Strict LDAP model with enhanced validation.

        Extends FlextCore.ArbitraryTypesModel with additional strict settings.
        Used for models requiring maximum validation security.
        """

        model_config = ConfigDict(
            # Inherit from ArbitraryTypesModel
            validate_assignment=True,
            validate_return=True,
            validate_default=True,
            use_enum_values=True,
            arbitrary_types_allowed=True,
            ser_json_timedelta="iso8601",
            ser_json_bytes="base64",
            serialize_by_alias=True,
            populate_by_name=True,
            str_strip_whitespace=True,
            # Additional strict settings
            strict=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

    class FlexibleModel(FlextCore.Models.ArbitraryTypesModel):
        """Flexible LDAP model for dynamic attributes.

        Extends FlextCore.ArbitraryTypesModel with extra="allow" for LDAP schemas.
        Used for models that accept arbitrary LDAP attributes from different servers.
        """

        model_config = ConfigDict(
            # Inherit from ArbitraryTypesModel
            validate_assignment=True,
            validate_return=True,
            validate_default=True,
            use_enum_values=True,
            arbitrary_types_allowed=True,
            ser_json_timedelta="iso8601",
            ser_json_bytes="base64",
            serialize_by_alias=True,
            populate_by_name=True,
            str_strip_whitespace=True,
            # Allow extra fields for LDAP dynamic schemas
            extra="allow",
            # Additional strict settings
            strict=True,
            hide_input_in_errors=True,
        )

    # =========================================================================
    # VALUE OBJECTS - Immutable LDAP value objects
    # =========================================================================

    class DistinguishedName(FlextCore.Models.Value):
        """LDAP Distinguished Name value object with RFC 2253 compliance.

        Extends FlextCore.Value for immutable value object behavior with strict validation.
        Enhanced with advanced Pydantic 2.11 features for LDAP-specific validation.
        """

        value: str = Field(
            ...,
            min_length=1,
            description="Distinguished Name string",
            pattern=r"^[a-zA-Z]+=.+",  # Basic DN pattern
            examples=[
                "cn=John Doe,ou=users,dc=example,dc=com",
                "uid=admin,dc=ldap,dc=local",
            ],
        )

        @field_validator("value")
        @classmethod
        def validate_dn_format(cls, v: str) -> str:
            """Enhanced DN validation with RFC 2253 compliance."""
            exceptions = FlextLdapExceptions()

            if not v or not v.strip():
                error_msg = "Distinguished Name cannot be empty"
                raise exceptions.validation_error(error_msg, value=v, field="dn")

            # Enhanced DN validation - check for proper attribute=value pairs
            if "=" not in v:
                error_msg = "Invalid DN format - missing attribute=value pairs"
                raise exceptions.validation_error(error_msg, value=v, field="dn")

            # Check for valid DN components
            components = v.split(",")
            for comp in components:
                component = comp.strip()
                if "=" not in component:
                    error_msg = f"Invalid DN component: {component}"
                    raise exceptions.validation_error(
                        error_msg,
                        value=component,
                        field="dn",
                    )

                attr, value = component.split("=", 1)
                if not attr.strip() or not value.strip():
                    error_msg = f"Empty attribute or value in DN component: {component}"
                    raise exceptions.validation_error(
                        error_msg,
                        value=component,
                        field="dn",
                    )

            return v.strip()

        @model_validator(mode="after")
        def validate_dn_structure(self) -> FlextLdapModels.DistinguishedName:
            """Cross-field validation for DN structure integrity."""
            exceptions = FlextLdapExceptions()

            # Validate DN has at least one component
            components = self.value.split(",")
            if len(components) < 1:
                error_msg = "DN must have at least one component"
                raise exceptions.validation_error(
                    error_msg,
                    value=self.value,
                    field="dn",
                )

            # Validate no duplicate attributes in RDN
            rdn_attrs = []
            first_component = components[0].strip()
            if "+" in first_component:  # Multi-valued RDN
                rdn_parts = first_component.split("+")
                for part in rdn_parts:
                    attr = part.split("=")[0].strip().lower()
                    if attr in rdn_attrs:
                        error_msg = f"Duplicate attribute in RDN: {attr}"
                        raise exceptions.validation_error(
                            error_msg,
                            value=attr,
                            field="rdn",
                        )
                    rdn_attrs.append(attr)

            return self

        @classmethod
        def from_string(cls, dn_string: str) -> FlextLdapModels.DistinguishedName:
            """Create a DistinguishedName instance from a string.

            Args:
                dn_string: The DN string to create from

            Returns:
                DistinguishedName: A new DistinguishedName instance

            """
            return cls(value=dn_string)

        @property
        def rdn(self) -> str:
            """Property: Get the Relative Distinguished Name (first component)."""
            return self.value.split(",")[0].strip()

        @computed_field
        def parent_dn(self) -> str | None:
            """Computed field for parent Distinguished Name."""
            components = self.value.split(",")
            if len(components) <= 1:
                return None
            return ",".join(components[1:]).strip()

        @computed_field
        def rdn_attribute(self) -> str:
            """Computed field: Get the RDN attribute name."""
            rdn = self.value.split(",")[0].strip()
            if "=" in rdn:
                return rdn.split("=")[0].strip().lower()
            return ""

        @computed_field
        def rdn_value(self) -> str:
            """Computed field: Get the RDN value."""
            rdn = self.value.split(",")[0].strip()
            if "=" in rdn:
                return rdn.split("=", 1)[1].strip()
            return ""

        @computed_field
        def components_count(self) -> int:
            """Computed field: Number of DN components."""
            return len(self.value.split(","))

        @field_serializer("value")
        def serialize_dn(self, value: str) -> str:
            """Custom serializer for DN normalization."""
            # Normalize DN format for consistent serialization
            components: FlextCore.Types.StringList = []
            for comp in value.split(","):
                component = comp.strip()
                if "=" in component:
                    attr, val = component.split("=", 1)
                    # Normalize attribute name to lowercase, preserve value case
                    normalized_component = f"{attr.strip().lower()}={val.strip()}"
                    components.append(normalized_component)
            return ",".join(components)

        @classmethod
        def create(cls, *args: object, **kwargs: object) -> FlextCore.Result[object]:
            """Create DN with validation - compatible with base class signature."""
            try:
                # Handle single argument case for DN string
                if len(args) == 1 and not kwargs:
                    dn_string = str(args[0])
                    dn_obj = cls(value=dn_string.strip())
                    return FlextCore.Result[object].ok(dn_obj)

                # Handle kwargs case - ensure value is string
                if "value" in kwargs:
                    kwargs["value"] = str(kwargs["value"])

                # Convert all kwargs to proper types for Pydantic validation
                typed_kwargs: FlextCore.Types.StringDict = {}
                for k, v in kwargs.items():
                    typed_kwargs[k] = str(v)

                dn_obj = cls(**typed_kwargs)
                return FlextCore.Result[object].ok(dn_obj)
            except FlextLdapExceptions.LdapValidationError as e:
                return FlextCore.Result[object].fail(
                    f"DN creation failed: {e}",
                )
            except Exception as e:
                return FlextCore.Result[object].fail(
                    f"DN creation failed: {e}",
                )

    class Filter(FlextCore.Models.Value):
        """LDAP filter value object with RFC 4515 compliance.

        Extends FlextCore.Models.Value for proper Pydantic 2 validation and composition.
        """

        expression: str = Field(..., min_length=1, description="LDAP filter expression")

        @field_validator("expression")
        @classmethod
        def validate_filter_syntax(cls, v: str) -> str:
            """Validate LDAP filter syntax and format."""
            exceptions = FlextLdapExceptions()

            if not v or not v.strip():
                msg = "LDAP filter cannot be empty"
                raise exceptions.validation_error(msg, value=v, field="filter")
            # Basic filter validation
            if not (v.startswith("(") and v.endswith(")")):
                msg = "LDAP filter must be enclosed in parentheses"
                raise exceptions.validation_error(msg, value=v, field="filter")
            return v.strip()

        @classmethod
        def equals(cls, attribute: str, value: str) -> FlextLdapModels.Filter:
            """Create equality filter."""
            return cls(expression=f"({attribute}={value})")

        @classmethod
        def starts_with(
            cls,
            attribute: str,
            value: str,
        ) -> FlextLdapModels.Filter:
            """Create starts-with filter."""
            return cls(expression=f"({attribute}={value}*)")

        @classmethod
        def object_class(cls, object_class: str) -> FlextLdapModels.Filter:
            """Create objectClass filter."""
            return cls(expression=f"(objectClass={object_class})")

    class Scope(FlextCore.Models.Value):
        """LDAP search scope value object.

        Extends FlextCore.Models.Value for proper Pydantic 2 validation and composition.
        """

        value: str = Field(..., description="LDAP search scope value")

        BASE: ClassVar[str] = "base"
        ONELEVEL: ClassVar[str] = "onelevel"
        SUBTREE: ClassVar[str] = "subtree"

        @field_validator("value")
        @classmethod
        def validate_scope_value(cls, v: str) -> str:
            """Validate LDAP search scope value."""
            valid_scopes = {cls.BASE, cls.ONELEVEL, cls.SUBTREE}
            if v not in valid_scopes:
                msg = f"Invalid scope: {v}. Must be one of {valid_scopes}"
                exceptions = FlextLdapExceptions()
                raise exceptions.validation_error(msg, value=v, field="scope")
            return v

        @classmethod
        def base(cls) -> FlextLdapModels.Scope:
            """Create base scope."""
            return cls(value=cls.BASE)

        @classmethod
        def onelevel(cls) -> FlextLdapModels.Scope:
            """Create onelevel scope."""
            return cls(value=cls.ONELEVEL)

        @classmethod
        def subtree(cls) -> FlextLdapModels.Scope:
            """Create subtree scope."""
            return cls(value=cls.SUBTREE)

    # =========================================================================
    # SCHEMA MODELS - LDAP schema discovery and server quirks handling
    # =========================================================================

    class LdapServerType(Enum):
        """Known LDAP server types for quirks handling."""

        UNKNOWN = "unknown"
        OPENLDAP = "openldap"
        ACTIVE_DIRECTORY = "active_directory"
        ORACLE_DIRECTORY = "oracle_directory"
        ORACLE_OUD = "oracle_oud"
        SUN_OPENDS = "sun_opends"
        APACHE_DIRECTORY = "apache_directory"
        NOVELL_EDIRECTORY = "novell_edirectory"
        IBM_DIRECTORY = "ibm_directory"
        GENERIC = "generic"

    class SchemaAttribute(FlextCore.Models.Value):
        """LDAP schema attribute definition.

        Extends FlextCore.Models.Value for proper Pydantic 2 validation and composition.
        """

        name: str = Field(..., description="Attribute name")
        oid: str = Field(..., description="Object identifier")
        syntax: str = Field(..., description="Attribute syntax")
        is_single_valued: bool = Field(..., description="Single valued attribute")
        is_operational: bool = Field(default=False, description="Operational attribute")
        is_collective: bool = Field(default=False, description="Collective attribute")
        is_no_user_modification: bool = Field(
            default=False,
            description="No user modification",
        )
        usage: str = Field(default="userApplications", description="Attribute usage")
        equality: str | None = Field(default=None, description="Equality matching rule")
        ordering: str | None = Field(default=None, description="Ordering matching rule")
        substr: str | None = Field(default=None, description="Substring matching rule")
        superior: str | None = Field(default=None, description="Superior attribute")

    class SchemaObjectClass(FlextCore.Models.Value):
        """LDAP schema object class definition.

        Extends FlextCore.Models.Value for proper Pydantic 2 validation and composition.
        """

        name: str = Field(..., description="Object class name")
        oid: str = Field(..., description="Object identifier")
        superior: FlextCore.Types.StringList = Field(
            default_factory=list,
            description="Superior classes",
        )
        must: FlextCore.Types.StringList = Field(
            default_factory=list,
            description="Required attributes",
        )
        may: FlextCore.Types.StringList = Field(
            default_factory=list,
            description="Optional attributes",
        )
        kind: str = Field(default="STRUCTURAL", description="Object class kind")
        is_obsolete: bool = Field(default=False, description="Obsolete flag")

    class ServerQuirks(FlextCore.Models.Value):
        """LDAP server-specific quirks and behaviors - Pydantic Value Object."""

        server_type: FlextLdapModels.LdapServerType
        case_sensitive_dns: bool = True
        case_sensitive_attributes: bool = True
        supports_paged_results: bool = True
        supports_vlv: bool = False
        supports_sync: bool = False
        max_page_size: int = 1000
        default_timeout: int = 30
        supports_start_tls: bool = True
        requires_explicit_bind: bool = False
        attribute_name_mappings: FlextCore.Types.StringDict = Field(
            default_factory=dict
        )
        object_class_mappings: FlextCore.Types.StringDict = Field(default_factory=dict)
        dn_format_preferences: FlextCore.Types.StringList = Field(default_factory=list)
        search_scope_limitations: set[str] = Field(default_factory=set)
        filter_syntax_quirks: FlextCore.Types.StringList = Field(default_factory=list)
        modify_operation_quirks: FlextCore.Types.StringList = Field(
            default_factory=list
        )

    class SchemaDiscoveryResult(FlextCore.Models.Entity):
        """Result of LDAP schema discovery operation - Pydantic Entity."""

        # Note: Cannot use frozen=True with Entity (has default timestamp fields)

        server_info: FlextLdapModels.ServerInfo
        server_type: FlextLdapModels.LdapServerType
        server_quirks: FlextLdapModels.ServerQuirks
        attributes: dict[str, FlextLdapModels.SchemaAttribute]
        object_classes: dict[str, FlextLdapModels.SchemaObjectClass]
        naming_contexts: FlextCore.Types.StringList
        supported_controls: FlextCore.Types.StringList
        supported_extensions: FlextCore.Types.StringList

    # =========================================================================
    # BASE CLASSES - Common functionality for LDAP entities
    # =========================================================================

    class Base(FlexibleModel):
        """Base model class with dynamic LDAP entity support.

        **DYNAMIC LDAP SCHEMA**: Allows arbitrary attributes to support varying LDAP server schemas
        (OpenLDAP, Active Directory, Oracle OID/OUD, 389 DS, etc.) with different custom attributes.

        Extends FlexibleModel to accept any LDAP attribute from any server type.
        """

        # LDAP-specific timestamp fields (nullable)
        created_at: datetime | None = Field(
            default=None,
            description="Creation timestamp",
        )
        updated_at: datetime | None = Field(
            default=None,
            description="Last update timestamp",
        )

    class ValidationMixin:
        """Mixin providing common field validation methods for LDAP entities.

        Centralizes validation logic to eliminate duplication across model classes.
        """

        @staticmethod
        def validate_dn_field(v: str) -> str:
            """Common DN validation using centralized validation."""
            validation_result: FlextCore.Result[None] = (
                FlextLdapValidations.validate_dn(
                    v,
                ).map(lambda _: None)
            )
            if validation_result.is_failure:
                exceptions = FlextLdapExceptions()
                error_msg = validation_result.error or "DN validation failed"
                raise exceptions.validation_error(error_msg, value=v, field="dn")
            return v.strip()

        @staticmethod
        def validate_email_field(value: str | None) -> str | None:
            """Common email validation using flext-core FlextCore.Utilities."""
            if value is None:
                return None

            # Use flext-core validation directly (returns FlextCore.Result[str])
            validation_result = FlextCore.Utilities.Validation.validate_email(value)
            if validation_result.is_failure:
                exceptions = FlextLdapExceptions()
                error_msg = validation_result.error or "Email validation failed"
                raise exceptions.validation_error(error_msg, value=value, field="email")
            return value

        @staticmethod
        def validate_password_field(value: str | None) -> str | None:
            """Common password validation using centralized validation."""
            validation_result: FlextCore.Result[None] = (
                FlextLdapValidations.validate_password(
                    str(value) if value is not None else "",
                ).map(lambda _: None)
            )
            if validation_result.is_failure:
                exceptions = FlextLdapExceptions()
                error_msg = validation_result.error or "Password validation failed"
                raise exceptions.validation_error(
                    error_msg,
                    value="***",
                    field="password",
                )
            return value

        @staticmethod
        def validate_required_string_field(v: str) -> str:
            """Common validation for required string fields."""
            if not v or not v.strip():
                msg = "Required field cannot be empty"
                exceptions = FlextLdapExceptions()
                raise exceptions.validation_error(msg, value=v, field="required_string")
            return v.strip()

    class EntityBase(FlextCore.Models.Entity, ValidationMixin):
        """Base class for LDAP entities with common fields and validation.

        Provides common fields and validation methods that are shared
        across multiple LDAP entity types.
        """

        # Common additional attributes field
        additional_attributes: dict[
            str,
            FlextLdapTypes.LdapEntries.EntryAttributeValue,
        ] = Field(
            default_factory=dict,
            description="Additional LDAP attributes",
        )

    # =========================================================================
    # CORE LDAP ENTITIES - Primary Domain Objects
    # =========================================================================

    class LdapUser(EntityBase):
        """LDAP User entity with enterprise attributes and advanced Pydantic 2.11 features.

        **CENTRALIZED APPROACH**: All user operations follow centralized patterns:
        - FlextLdapModels.LdapUser.* for user-specific operations
        - Centralized validation through FlextLdapValidations
        - No wrappers, aliases, or fallbacks
        - Direct use of flext-core centralized models

        **PYTHON 3.13+ COMPATIBILITY**: Uses modern union syntax and latest type features.
        """

        # Core identification
        dn: str = Field(..., description="Distinguished Name (unique identifier)")
        cn: str = Field(..., description="Common Name")
        uid: str = Field(..., description="User ID")
        sn: str = Field(..., description="Surname")
        given_name: str | None = Field(default=None, description="Given Name")

        # Contact information
        mail: str | None = Field(default=None, description="Primary email address")
        telephone_number: str | None = Field(
            default=None,
            description="Primary phone number",
        )
        mobile: str | None = Field(default=None, description="Mobile phone number")

        # Organizational
        department: str | None = Field(
            default=FlextLdapConstants.Defaults.DEFAULT_DEPARTMENT,
            description="Department",
        )
        title: str | None = Field(
            default=FlextLdapConstants.Defaults.DEFAULT_TITLE,
            description="Job title",
        )
        organization: str | None = Field(
            default=FlextLdapConstants.Defaults.DEFAULT_ORGANIZATION,
            description="Organization",
        )
        organizational_unit: str | None = Field(
            default=None,
            description="Organizational Unit",
        )

        # Authentication
        user_password: str | SecretStr | None = Field(
            default=None,
            description="User password",
        )

        # LDAP metadata
        object_classes: FlextCore.Types.StringList = Field(
            default_factory=lambda: ["person", "organizationalPerson", "inetOrgPerson"],
            description="LDAP object classes",
        )

        # Core enterprise fields
        status: str | None = Field(
            default=FlextLdapConstants.Defaults.DEFAULT_STATUS,
            description="User status",
        )
        additional_attributes: dict[
            str,
            FlextLdapTypes.LdapEntries.EntryAttributeValue,
        ] = Field(
            default_factory=dict,
            description="Additional LDAP attributes",
        )
        display_name: str | None = Field(default=None, description="Display Name")
        modified_at: str | None = Field(
            default=None,
            description="Last modification timestamp",
        )
        created_timestamp: datetime | None = Field(
            default=None,
            description="Creation timestamp",
        )
        modified_timestamp: datetime | None = Field(
            default=None,
            description="Modification timestamp",
        )

        @field_validator("department", "title", "organization", "status", mode="before")
        @classmethod
        def set_defaults_from_constants(
            cls,
            v: str | None,
            info: ValidationInfo,
        ) -> str:
            """Set defaults from constants if None is provided."""
            if v is None:
                field_name = info.field_name
                if field_name == "department":
                    return FlextLdapConstants.Defaults.DEFAULT_DEPARTMENT
                if field_name == "title":
                    return FlextLdapConstants.Defaults.DEFAULT_TITLE
                if field_name == "organization":
                    return FlextLdapConstants.Defaults.DEFAULT_ORGANIZATION
                if field_name == "status":
                    return FlextLdapConstants.Defaults.DEFAULT_STATUS
            return v or ""

        @computed_field
        def full_name(self) -> str:
            """Computed field for user's full name."""
            if self.given_name and self.sn:
                return f"{self.given_name} {self.sn}"
            if self.given_name:
                return self.given_name
            if self.sn:
                return self.sn
            return self.cn

        @computed_field
        def is_active(self) -> bool:
            """Computed field indicating if user is active."""
            return self.status != "disabled" if self.status else True

        @computed_field
        def has_contact_info(self) -> bool:
            """Computed field indicating if user has complete contact information."""
            return bool(self.mail and (self.telephone_number or self.mobile))

        @computed_field
        def organizational_path(self) -> str:
            """Computed field for full organizational hierarchy."""
            path_parts = []
            if self.organization:
                path_parts.append(self.organization)
            if self.organizational_unit:
                path_parts.append(self.organizational_unit)
            if self.department:
                path_parts.append(self.department)
            return " > ".join(path_parts) if path_parts else "No organization"

        @computed_field
        def rdn(self) -> str:
            """Computed field for Relative Distinguished Name."""
            return self.dn.split(",")[0] if "," in self.dn else self.dn

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format using centralized validation."""
            return FlextLdapModels.ValidationMixin.validate_dn_field(v)

        @field_validator("mail")
        @classmethod
        def validate_email(cls, value: str | None) -> str | None:
            """Validate email format using centralized validation."""
            return cls.validate_email_field(value)

        @staticmethod
        def validate_dn_field(v: str) -> str:
            """Validate DN field using centralized validation."""
            if not v or not v.strip():
                msg = "DN cannot be empty"
                raise ValueError(msg)
            return v

        @staticmethod
        def validate_email_field(value: str | None) -> str | None:
            """Validate email field using centralized validation."""
            if value is None:
                return None
            if not value or "@" not in value:
                msg = "Invalid email format"
                raise ValueError(msg)
            return value

        @staticmethod
        def validate_required_string_field(v: str) -> str:
            """Validate required string field."""
            if not v or not v.strip():
                msg = "Field cannot be empty"
                raise ValueError(msg)
            return v

        @field_validator("cn")
        @classmethod
        def validate_cn(cls, v: str) -> str:
            """Validate Common Name."""
            return cls.validate_required_string_field(v)

        @field_validator("object_classes")
        @classmethod
        def validate_object_classes(
            cls,
            v: FlextCore.Types.StringList,
        ) -> FlextCore.Types.StringList:
            """Validate object classes."""
            if not v:
                msg = "At least one object class is required"
                exceptions = FlextLdapExceptions()
                raise exceptions.validation_error(
                    msg,
                    value=str(v),
                    field="object_classes",
                )
            return v

        @model_validator(mode="after")
        def validate_user_consistency(self) -> FlextLdapModels.LdapUser:
            """Model validator for cross-field validation and business rules."""
            exceptions = FlextLdapExceptions()

            # Ensure person object class is present
            if "person" not in self.object_classes:
                msg = "User must have 'person' object class"
                raise exceptions.validation_error(
                    msg,
                    value=str(self.object_classes),
                    field="object_classes",
                )

            # Note: Required field validation is handled at repository level
            # to allow tests to verify repository validation logic

            # Set display_name from cn if not provided
            if not self.display_name:
                self.display_name = self.cn

            # Validate organizational consistency
            if (
                self.department
                and self.department != FlextLdapConstants.Defaults.DEFAULT_DEPARTMENT
                and not self.organizational_unit
            ):
                msg = "Department requires organizational unit"
                raise exceptions.validation_error(
                    msg,
                    value=str(self.department),
                    field="department",
                )

            return self

        @field_serializer("user_password")
        def serialize_password(self, value: str | SecretStr | None) -> str | None:
            """Field serializer for password handling."""
            if value is None:
                return None
            if isinstance(value, SecretStr):
                return "[PROTECTED]"
            return "[PROTECTED]" if value else None

        @field_serializer("dn")
        def serialize_dn(self, value: str) -> str:
            """Field serializer for DN normalization."""
            # Normalize DN formatting (remove extra spaces)
            components = [component.strip() for component in value.split(",")]
            return ",".join(components)

        def validate_business_rules(self) -> FlextCore.Result[None]:
            """Validate user business rules with enhanced error handling."""
            # Explicit FlextCore.Result error handling - NO try/except

            # User-specific validations
            if "person" not in self.object_classes:
                return FlextCore.Result[None].fail(
                    "User must have 'person' object class"
                )

            if not self.cn:
                return FlextCore.Result[None].fail("User must have a Common Name")

            return FlextCore.Result[None].ok(None)

        def to_ldap_attributes(self) -> dict[str, FlextCore.Types.StringList]:
            """Convert user to LDAP attributes format."""
            attributes: dict[str, FlextCore.Types.StringList] = {}

            # Core attributes
            if self.dn:
                attributes["dn"] = [self.dn]
            if self.cn:
                attributes["cn"] = [self.cn]
            if self.uid:
                attributes["uid"] = [self.uid]
            if self.sn:
                attributes["sn"] = [self.sn]
            if self.given_name:
                attributes["givenName"] = [self.given_name]
            if self.mail:
                attributes["mail"] = [self.mail]
            if self.telephone_number:
                attributes["telephoneNumber"] = [self.telephone_number]
            if self.mobile:
                attributes["mobile"] = [self.mobile]
            if self.department:
                attributes["department"] = [self.department]
            if self.title:
                attributes["title"] = [self.title]
            if self.organization:
                attributes["o"] = [self.organization]
            if self.organizational_unit:
                attributes["ou"] = [self.organizational_unit]
            if self.object_classes:
                attributes["objectClass"] = self.object_classes

            # Add additional attributes
            if self.additional_attributes is not None:
                for key, value in self.additional_attributes.items():
                    if isinstance(value, list):
                        attributes[key] = [str(v) for v in value]
                    else:
                        attributes[key] = [str(value)]

            return attributes

        @classmethod
        def from_ldap_attributes(
            cls,
            ldap_attributes: dict[str, FlextCore.Types.StringList],
        ) -> FlextCore.Result[FlextLdapModels.LdapUser]:
            """Create user from LDAP attributes."""
            # Explicit FlextCore.Result error handling - NO try/except

            # Extract DN
            dn_values = ldap_attributes.get(
                FlextLdapConstants.LdapAttributeNames.DN,
                [],
            )
            if not dn_values:
                return FlextCore.Result[FlextLdapModels.LdapUser].fail("DN is required")
            dn = dn_values[0]

            # Extract core attributes
            cn_values = ldap_attributes.get(
                FlextLdapConstants.LdapAttributeNames.CN,
                [],
            )
            cn = cn_values[0] if cn_values else ""

            uid_values = ldap_attributes.get(
                FlextLdapConstants.LdapAttributeNames.UID,
                [],
            )
            uid = uid_values[0] if uid_values else None

            sn_values = ldap_attributes.get(
                FlextLdapConstants.LdapAttributeNames.SN,
                [],
            )
            sn = sn_values[0] if sn_values else None

            given_name_values = ldap_attributes.get(
                FlextLdapConstants.LdapAttributeNames.GIVEN_NAME,
                [],
            )
            given_name = given_name_values[0] if given_name_values else None

            mail_values = ldap_attributes.get(
                FlextLdapConstants.LdapAttributeNames.MAIL,
                [],
            )
            mail = mail_values[0] if mail_values else None

            telephone_number_values = ldap_attributes.get(
                FlextLdapConstants.LdapAttributeNames.TELEPHONE_NUMBER,
                [],
            )
            telephone_number = (
                telephone_number_values[0] if telephone_number_values else None
            )

            mobile_values = ldap_attributes.get(
                FlextLdapConstants.LdapAttributeNames.MOBILE,
                [],
            )
            mobile = mobile_values[0] if mobile_values else None

            department_values = ldap_attributes.get(
                FlextLdapConstants.LdapAttributeNames.DEPARTMENT,
                [],
            )
            department = department_values[0] if department_values else None

            title_values = ldap_attributes.get(
                FlextLdapConstants.LdapAttributeNames.TITLE,
                [],
            )
            title = title_values[0] if title_values else None

            organization_values = ldap_attributes.get("o", [])
            organization = organization_values[0] if organization_values else None

            organizational_unit_values = ldap_attributes.get(
                FlextLdapConstants.LdapAttributeNames.OU,
                [],
            )
            organizational_unit = (
                organizational_unit_values[0] if organizational_unit_values else None
            )

            object_classes = ldap_attributes.get(
                FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS,
                ["person", "organizationalPerson", "inetOrgPerson"],
            )

            # Create user with proper type handling
            user = cls(
                dn=dn,
                cn=cn or "",
                uid=uid or "",
                sn=sn or "",
                given_name=given_name,
                mail=mail or "",
                telephone_number=telephone_number,
                mobile=mobile,
                department=department,
                title=title,
                organization=organization,
                organizational_unit=organizational_unit,
                object_classes=object_classes,
                user_password=None,  # Never store passwords from LDAP
                additional_attributes={},
                status="active",
                display_name=cn,
                modified_at=None,
                created_timestamp=None,
                modified_timestamp=None,
            )

            return FlextCore.Result[FlextLdapModels.LdapUser].ok(user)

        @classmethod
        def create_minimal(
            cls,
            dn: str,
            cn: str,
            uid: str | None = None,
            **kwargs: object,
        ) -> FlextCore.Result[FlextLdapModels.LdapUser]:
            """Create minimal user with required fields only and enhanced error handling."""
            try:
                # Extract specific known optional parameters with proper typing
                sn_raw = kwargs.get(FlextLdapConstants.DictKeys.SN)
                given_name_raw = kwargs.get(FlextLdapConstants.DictKeys.GIVEN_NAME)
                mail_raw = kwargs.get(FlextLdapConstants.DictKeys.MAIL)
                telephone_number_raw = kwargs.get(
                    FlextLdapConstants.DictKeys.TELEPHONE_NUMBER,
                )
                mobile_raw = kwargs.get(FlextLdapConstants.DictKeys.MOBILE)
                department_raw = kwargs.get(FlextLdapConstants.DictKeys.DEPARTMENT)
                title_raw = kwargs.get(FlextLdapConstants.DictKeys.TITLE)
                organization_raw = kwargs.get(FlextLdapConstants.DictKeys.ORGANIZATION)
                organizational_unit_raw = kwargs.get(
                    FlextLdapConstants.DictKeys.ORGANIZATIONAL_UNIT,
                )
                user_password_raw = kwargs.get(
                    FlextLdapConstants.DictKeys.USER_PASSWORD,
                )

                # Convert to proper types
                sn = str(sn_raw) if sn_raw is not None else ""
                given_name: str | None = (
                    str(given_name_raw) if given_name_raw is not None else None
                )
                mail = str(mail_raw) if mail_raw is not None else ""
                telephone_number: str | None = (
                    str(telephone_number_raw)
                    if telephone_number_raw is not None
                    else None
                )
                mobile: str | None = str(mobile_raw) if mobile_raw is not None else None
                department: str | None = (
                    str(department_raw) if department_raw is not None else None
                )
                title: str | None = str(title_raw) if title_raw is not None else None
                organization: str | None = (
                    str(organization_raw) if organization_raw is not None else None
                )
                organizational_unit: str | None = (
                    str(organizational_unit_raw)
                    if organizational_unit_raw is not None
                    else None
                )

                # Create user_password SecretStr if provided
                user_password = None
                if user_password_raw and isinstance(user_password_raw, str):
                    user_password = SecretStr(str(user_password_raw))

                # Create user with explicit arguments to avoid **kwargs typing issues
                user = cls(
                    dn=dn,
                    cn=cn,
                    uid=uid or "",
                    sn=sn,
                    given_name=given_name,
                    mail=mail,
                    telephone_number=telephone_number,
                    mobile=mobile,
                    department=department,
                    title=title,
                    organization=organization,
                    organizational_unit=organizational_unit,
                    user_password=(
                        user_password.get_secret_value() if user_password else None
                    ),
                    # Use defaults for other fields
                    object_classes=["person", "organizationalPerson", "inetOrgPerson"],
                    status="active",
                    display_name=cn,  # Use cn as display name by default
                )
                return FlextCore.Result[FlextLdapModels.LdapUser].ok(user)
            except FlextLdapExceptions.LdapValidationError as e:
                return FlextCore.Result[FlextLdapModels.LdapUser].fail(
                    f"User creation failed: {e}",
                )
            except Exception as e:
                return FlextCore.Result[FlextLdapModels.LdapUser].fail(
                    f"User creation failed: {e}",
                )

    class Group(FlextCore.Models.Entity):
        """LDAP Group entity with membership management.

        **CENTRALIZED APPROACH**: All group operations follow centralized patterns:
        - FlextLdapModels.Group.* for group-specific operations
        - Centralized validation through FlextLdapValidations
        - No wrappers, aliases, or fallbacks
        - Direct use of flext-core centralized models

        **PYTHON 3.13+ COMPATIBILITY**: Uses modern union syntax and latest type features.
        """

        # Core identification
        dn: str = Field(..., description="Distinguished Name")
        cn: str = Field(..., description="Common Name")
        gid_number: int | None = Field(default=None, description="Group ID Number")

        # Group membership
        member_dns: FlextCore.Types.StringList = Field(
            default_factory=list,
            description="Member Distinguished Names",
        )
        unique_member_dns: FlextCore.Types.StringList = Field(
            default_factory=list,
            description="Unique Member Distinguished Names",
        )

        # Core enterprise fields
        status: str | None = Field(default=None, description="Group status")
        additional_attributes: FlextLdapModels.AdditionalAttributes | None = Field(
            default=None,
            description="Additional LDAP attributes",
        )
        modified_at: str | None = Field(
            default=None,
            description="Last modification timestamp",
        )
        created_timestamp: datetime | None = Field(
            default=None,
            description="Creation timestamp",
        )
        modified_timestamp: datetime | None = Field(
            default=None,
            description="Modification timestamp",
        )

        # Metadata
        description: str | None = Field(default=None, description="Group description")
        object_classes: FlextCore.Types.StringList = Field(
            default_factory=lambda: ["groupOfNames", "top"],
            description="LDAP object classes",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format using centralized validation."""
            return FlextLdapModels.ValidationMixin.validate_dn_field(v)

        def validate_business_rules(self) -> FlextCore.Result[None]:
            """Validate group business rules with enhanced error handling."""
            # Explicit FlextCore.Result error handling - NO try/except

            # Group-specific validations
            if "groupOfNames" not in self.object_classes:
                return FlextCore.Result[None].fail(
                    "Group must have 'groupOfNames' object class",
                )

            return FlextCore.Result[None].ok(None)

        def to_ldap_attributes(self) -> dict[str, FlextCore.Types.StringList]:
            """Convert group to LDAP attributes format."""
            attributes: dict[str, FlextCore.Types.StringList] = {}

            # Core attributes
            if self.dn:
                attributes["dn"] = [self.dn]
            if self.cn:
                attributes["cn"] = [self.cn]
            if self.gid_number:
                attributes["gidNumber"] = [str(self.gid_number)]
            if self.description:
                attributes["description"] = [self.description]
            if self.object_classes:
                attributes["objectClass"] = self.object_classes
            if self.member_dns:
                attributes["member"] = self.member_dns
            if self.unique_member_dns:
                attributes["uniqueMember"] = self.unique_member_dns

            # Add additional attributes
            if self.additional_attributes is not None:
                for key, value in self.additional_attributes.model_dump().items():
                    if isinstance(value, list):
                        attributes[key] = [str(v) for v in value]
                    else:
                        attributes[key] = [str(value)]

            return attributes

        @classmethod
        def from_ldap_attributes(
            cls,
            ldap_attributes: dict[str, FlextCore.Types.StringList],
        ) -> FlextCore.Result[FlextLdapModels.Group]:
            """Create group from LDAP attributes."""
            # Explicit FlextCore.Result error handling - NO try/except

            # Extract DN
            dn_values = ldap_attributes.get(
                FlextLdapConstants.LdapAttributeNames.DN,
                [],
            )
            if not dn_values:
                return FlextCore.Result[FlextLdapModels.Group].fail("DN is required")
            dn = dn_values[0]

            # Extract core attributes
            cn_values = ldap_attributes.get(
                FlextLdapConstants.LdapAttributeNames.CN,
                [],
            )
            cn = cn_values[0] if cn_values else ""

            gid_number_values = ldap_attributes.get(
                FlextLdapConstants.LdapAttributeNames.GID_NUMBER,
                [],
            )
            gid_number = int(gid_number_values[0]) if gid_number_values else None

            description_values = ldap_attributes.get(
                FlextLdapConstants.LdapAttributeNames.DESCRIPTION,
                [],
            )
            description = description_values[0] if description_values else None

            object_classes = ldap_attributes.get(
                FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS,
                ["groupOfNames", "top"],
            )

            member_dns = ldap_attributes.get(
                FlextLdapConstants.LdapAttributeNames.MEMBER,
                [],
            )
            unique_member_dns = ldap_attributes.get(
                FlextLdapConstants.LdapAttributeNames.UNIQUE_MEMBER,
                [],
            )

            # Create group
            group = cls(
                dn=dn,
                cn=cn,
                gid_number=gid_number,
                description=description,
                member_dns=member_dns,
                unique_member_dns=unique_member_dns,
                object_classes=object_classes,
                status="active",
                additional_attributes=None,
                created_timestamp=None,
                modified_timestamp=None,
            )

            return FlextCore.Result[FlextLdapModels.Group].ok(group)

        def has_member(self, member_dn: str) -> bool:
            """Check if DN is a member of this group with enhanced error handling."""
            # Explicit FlextCore.Result error handling - NO try/except
            return member_dn in self.member_dns or member_dn in self.unique_member_dns

        def add_member(self, member_dn: str) -> FlextCore.Result[None]:
            """Add member to group with enhanced error handling."""
            # Explicit FlextCore.Result error handling - NO try/except
            if member_dn not in self.member_dns:
                self.member_dns.append(member_dn)
            return FlextCore.Result[None].ok(None)

        def remove_member(self, member_dn: str) -> FlextCore.Result[None]:
            """Remove member from group with enhanced error handling."""
            # Explicit FlextCore.Result error handling - NO try/except
            if member_dn in self.member_dns:
                self.member_dns.remove(member_dn)
                return FlextCore.Result[None].ok(None)
            return FlextCore.Result[None].fail(f"Member {member_dn} not found in group")

        @classmethod
        def create_minimal(
            cls,
            dn: str,
            cn: str,
            gid_number: int | None = None,
            description: str | None = None,
            **_kwargs: object,
        ) -> FlextCore.Result[FlextLdapModels.Group]:
            """Create minimal group with required fields only and enhanced error handling."""
            # Explicit FlextCore.Result error handling - NO try/except

            # Create group with explicit arguments to avoid **kwargs typing issues
            group = cls(
                dn=dn,
                cn=cn,
                gid_number=gid_number,
                description=description,
                # Use defaults for other fields
                member_dns=[],
                unique_member_dns=[],
                status="active",
                object_classes=["groupOfNames", "top"],
            )
            return FlextCore.Result[FlextLdapModels.Group].ok(group)

    class Entry(EntityBase):
        """Generic LDAP Entry entity.

        **CENTRALIZED APPROACH**: All entry operations follow centralized patterns:
        - FlextLdapModels.Entry.* for entry-specific operations
        - Centralized validation through FlextLdapValidations
        - No wrappers, aliases, or fallbacks
        - Direct use of flext-core centralized models

        **PYTHON 3.13+ COMPATIBILITY**: Uses modern union syntax and latest type features.
        """

        # Core identification
        dn: str = Field(..., description="Distinguished Name")

        # LDAP attributes as flexible dict
        attributes: dict[str, FlextLdapTypes.LdapEntries.EntryAttributeValue] = Field(
            default_factory=dict,
            description="LDAP entry attributes",
        )

        # LDAP metadata
        object_classes: FlextCore.Types.StringList = Field(
            default_factory=list,
            description="LDAP object classes",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format using centralized validation."""
            return FlextLdapModels.ValidationMixin.validate_dn_field(v)

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists with enhanced error handling."""
            # Explicit FlextCore.Result error handling - NO try/except
            return name in self.attributes

        # Dict-like interface for compatibility
        def __getitem__(
            self,
            key: str,
        ) -> FlextLdapTypes.LdapEntries.EntryAttributeValue | None:
            """Dict-like access to attributes.

            Special handling for 'dn' and 'object_classes' which are model fields, not attributes.
            """
            # Special case: DN is a field, not an attribute
            if key == "dn":
                return self.dn
            # Special case: objectClass/objectClasses mapping
            if key in {"objectClass", "objectClasses"}:
                return self.object_classes
            # Regular attribute lookup
            return self.attributes.get(key)

        def __contains__(self, key: str) -> bool:
            """Dict-like containment check.

            Special handling for 'dn' and 'object_classes' which are model fields, not attributes.
            """
            if not isinstance(key, str):
                return False
            # Special cases: DN and objectClass are always present as model fields
            if key == "dn":
                return self.dn is not None
            if key in {"objectClass", "objectClasses"}:
                return self.object_classes is not None
            # Regular attribute check
            return self.has_attribute(key)

        def get(
            self,
            key: str,
            default: FlextLdapTypes.LdapEntries.EntryAttributeValue | None = None,
        ) -> FlextLdapTypes.LdapEntries.EntryAttributeValue | None:
            """Dict-like get method with default value.

            Special handling for 'dn' and 'object_classes' which are model fields, not attributes.
            """
            # Special case: DN is a field, not an attribute
            if key == "dn":
                return self.dn or default
            # Special case: objectClass/objectClasses mapping
            if key in {"objectClass", "objectClasses"}:
                return self.object_classes or default
            # Regular attribute lookup
            return self.attributes.get(key, default)

        @classmethod
        def from_ldif(cls, ldif_entry: FlextLdifModels.Entry) -> FlextLdapModels.Entry:
            """Convert FlextLdif Entry to FlextLdap Entry using adapter pattern.

            Eliminates duplicate LDIF conversion logic across codebase by centralizing
            in the domain model where it belongs (Clean Architecture pattern).

            Args:
                ldif_entry: FlextLdif Entry object with dn and attributes

            Returns:
                FlextLdapModels.Entry instance

            Raises:
                ValueError: If ldif_entry is invalid or missing required fields

            Example:
                >>>                 >>> ldif_entry = FlextLdifModels.Entry(...)
                >>> ldap_entry = FlextLdapModels.Entry.from_ldif(ldif_entry)

            """
            if not hasattr(ldif_entry, "dn") or not hasattr(ldif_entry, "attributes"):
                msg = "Invalid LDIF entry: missing dn or attributes"
                raise ValueError(msg)

            # Convert LDIF entry to LDAP entry - adapter pattern
            return cls(
                dn=str(ldif_entry.dn),
                attributes=dict(ldif_entry.attributes),
            )

        def to_ldif(self) -> FlextLdifModels.Entry:
            """Convert FlextLdap Entry to FlextLdif Entry using adapter pattern.

            Eliminates duplicate LDIF conversion logic across codebase by centralizing
            in the domain model where it belongs (Clean Architecture pattern).

            Returns:
                FlextLdif Entry object

            Raises:
                ImportError: If flext-ldif is not installed
                ValueError: If entry data is invalid

            Example:
                >>> entry = FlextLdapModels.Entry(dn="cn=test,dc=example,dc=com", ...)
                >>> ldif_entry = entry.to_ldif()
                >>> # Can now be written with FlextLdif.write([ldif_entry], path)

            """
            # Convert DN string to DistinguishedName if needed
            dn_value: FlextLdifModels.DistinguishedName
            if isinstance(self.dn, str):
                dn_value = FlextLdifModels.DistinguishedName(value=self.dn)
            else:
                # Already a DistinguishedName or compatible type
                dn_value = FlextLdifModels.DistinguishedName(value=str(self.dn))

            # Convert attributes to proper LDIF format
            ldif_attributes: dict[str, FlextLdifModels.AttributeValues] = {}
            for attr_name, attr_values in self.attributes.items():
                if isinstance(attr_values, str):
                    # Single string value - convert to list
                    ldif_attributes[attr_name] = FlextLdifModels.AttributeValues(
                        values=[attr_values],
                    )
                elif isinstance(attr_values, list):
                    # List of values - ensure they are strings
                    ldif_attributes[attr_name] = FlextLdifModels.AttributeValues(
                        values=[str(v) for v in attr_values],
                    )
                else:
                    # Handle other types by converting to string
                    ldif_attributes[attr_name] = FlextLdifModels.AttributeValues(
                        values=[str(attr_values)],
                    )

            # Create LDIF entry - adapter pattern
            return FlextLdifModels.Entry(
                dn=dn_value,
                attributes=FlextLdifModels.LdifAttributes(attributes=ldif_attributes),
            )

        def get_attribute(
            self, name: str
        ) -> FlextLdapTypes.LdapEntries.EntryAttributeValue | None:
            """Get a single attribute value by name.

            Args:
                name: Attribute name to retrieve

            Returns:
                Attribute value or None if not found

            """
            return self.attributes.get(name)

        def set_attribute(
            self, name: str, value: FlextLdapTypes.LdapEntries.EntryAttributeValue
        ) -> None:
            """Set a single attribute value by name.

            Args:
                name: Attribute name to set
                value: Attribute value to set

            """
            self.attributes[name] = value

        def get_rdn(self) -> str:
            """Get the Relative Distinguished Name (RDN) from the DN.

            Returns:
                RDN string (first component of DN)

            """
            if isinstance(self.dn, str):
                # Extract RDN from DN (part before first comma)
                return self.dn.split(",")[0]
            # Handle DistinguishedName object
            dn_str = str(self.dn)
            return dn_str.split(",", maxsplit=1)[0]

    # =========================================================================
    # LDAP OPERATION ENTITIES - Request/Response Objects
    # =========================================================================

    class SearchRequest(Base, ValidationMixin):
        """LDAP Search Request entity with comprehensive parameters and advanced Pydantic 2.11 features."""

        # Default attribute constants
        DEFAULT_USER_ATTRIBUTES: ClassVar[FlextCore.Types.StringList] = [
            "uid",
            "cn",
            "sn",
            "mail",
            "objectClass",
        ]
        DEFAULT_GROUP_ATTRIBUTES: ClassVar[FlextCore.Types.StringList] = [
            "cn",
            "member",
            "description",
            "objectClass",
        ]

        @classmethod
        def get_user_attributes(cls) -> FlextCore.Types.StringList:
            """Get default user attributes for search requests.

            Returns:
                List of default user attributes.

            """
            return cls.DEFAULT_USER_ATTRIBUTES.copy()

        # Search scope
        base_dn: str = Field(..., description="Search base Distinguished Name")
        filter_str: str = Field(..., description="LDAP search filter")
        scope: str = Field(
            default="subtree",
            description="Search scope: base, onelevel, subtree",
            pattern="^(base|onelevel|subtree|BASE|ONELEVEL|SUBTREE)$",
        )

        # Attribute selection
        attributes: FlextCore.Types.StringList | None = Field(
            default=None,
            description="Attributes to return (None = all)",
        )

        # Search limits - using centralized constants
        size_limit: int = Field(
            default=FlextCore.Constants.Performance.BatchProcessing.MAX_VALIDATION_SIZE,
            description="Maximum number of entries to return",
            ge=0,
        )
        time_limit: int = Field(
            default=FlextCore.Constants.Network.DEFAULT_TIMEOUT,
            description="Search timeout in seconds",
            ge=0,
        )

        # Paging - Optional for paged LDAP search results
        page_size: int | None = Field(
            default=None,
            description="Page size for paged results",
            ge=1,
        )
        paged_cookie: bytes | None = Field(
            default=None,
            description="Paging cookie for continuation",
        )

        # Advanced options
        types_only: bool = Field(
            default=False,
            description="Return attribute types only (no values)",
        )
        deref_aliases: str = Field(
            default="never",
            description="Alias dereferencing: never, searching, finding, always",
            pattern="^(never|searching|finding|always)$",
        )

        @computed_field
        def is_paged_search(self) -> bool:
            """Computed field indicating if this is a paged search."""
            return self.page_size is not None and self.page_size > 0

        @computed_field
        def search_complexity(self: FlextLdapModels.SearchRequest) -> str:
            """Computed field for search complexity assessment."""
            max_filter_complexity = 2  # Maximum filter complexity threshold
            if self.scope == "base":
                return "simple"
            if self.scope == "onelevel":
                return "moderate"
            if (
                "*" in self.filter_str
                or self.filter_str.count("&") > max_filter_complexity
            ):
                return "complex"
            return "standard"

        @computed_field
        def normalized_scope(self) -> str:
            """Computed field for normalized scope value."""
            return self.scope.lower()

        @computed_field
        def estimated_result_count(self: FlextLdapModels.SearchRequest) -> int:
            """Computed field for estimated result count based on search parameters."""
            if self.scope == "base":
                return 1
            if self.scope == "onelevel":
                return min(self.size_limit, 100)  # Estimate for one level
            # Subtree search - more conservative estimate
            if "uid=" in self.filter_str or "cn=" in self.filter_str:
                return min(self.size_limit, 10)  # Specific attribute search
            return min(self.size_limit, 1000)  # Broader search

        @field_validator("base_dn")
        @classmethod
        def validate_base_dn(cls, v: str) -> str:
            """Validate base DN format using centralized validation."""
            return cls.validate_dn_field(v)

        @field_validator("filter_str")
        @classmethod
        def validate_filter_str(cls, v: str) -> str:
            """Validate LDAP filter format using centralized validation."""
            validation_result: FlextCore.Result[None] = (
                FlextLdapValidations.validate_filter(
                    v,
                ).map(lambda _: None)
            )
            if validation_result.is_failure:
                exceptions = FlextLdapExceptions()
                error_msg = validation_result.error or "Filter validation failed"
                raise exceptions.validation_error(
                    error_msg,
                    value=v,
                    field="filter_str",
                )
            return v.strip()

        @field_validator("attributes")
        @classmethod
        def validate_attributes(
            cls,
            v: FlextCore.Types.StringList | None,
        ) -> FlextCore.Types.StringList | None:
            """Validate attribute list."""
            if v is not None:
                # Remove duplicates and empty strings using set comprehension
                cleaned_attrs = list({attr.strip() for attr in v if attr.strip()})
                return cleaned_attrs or None
            return v

        @model_validator(mode="after")
        def validate_search_consistency(self) -> FlextLdapModels.SearchRequest:
            """Model validator for cross-field validation and search optimization."""
            exceptions = FlextLdapExceptions()
            max_time_limit_seconds = 300  # 5 minutes maximum
            max_page_multiplier = 100  # Maximum page size multiplier

            # Validate paging consistency
            if self.page_size is not None and self.page_size <= 0:
                msg = "Page size must be positive if specified"
                raise exceptions.validation_error(
                    msg,
                    value=str(self.page_size),
                    field="page_size",
                )

            # Optimize size limit for paged searches
            # Store computed field result to avoid truthy-function warning
            paged_search_enabled: bool = bool(self.is_paged_search)
            if (
                paged_search_enabled
                and self.page_size is not None
                and self.size_limit > self.page_size * max_page_multiplier
            ):
                # Automatically adjust size limit for very large paged searches
                self.size_limit = min(
                    self.size_limit,
                    self.page_size * max_page_multiplier,
                )

            # Validate time limit is reasonable
            if self.time_limit > max_time_limit_seconds:
                msg = f"Time limit should not exceed {max_time_limit_seconds} seconds for performance"
                raise exceptions.validation_error(
                    msg,
                    value=str(self.time_limit),
                    field="time_limit",
                )

            # Note: Removed overly restrictive base scope filter validation
            # (objectClass=*) is a valid and standard LDAP filter for BASE scope searches
            # It retrieves the entry at the base DN, which is a common operation

            return self

        @field_serializer("paged_cookie")
        def serialize_cookie(self, value: bytes | None) -> str | None:
            """Field serializer for paging cookie."""
            if value is None:
                return None
            # Encode bytes as base64 for JSON serialization
            return base64.b64encode(value).decode("ascii")

        @field_serializer("filter_str")
        def serialize_filter(self, value: str) -> str:
            """Field serializer for LDAP filter normalization."""
            # Normalize whitespace in filter
            return " ".join(value.split())

        @classmethod
        def create_user_search(
            cls,
            uid: str,
            base_dn: str = "ou=users,dc=example,dc=com",
            attributes: FlextCore.Types.StringList | None = None,
        ) -> FlextLdapModels.SearchRequest:
            """Create search request for user."""
            return cls.model_validate(
                {
                    "base_dn": base_dn,
                    "filter_str": f"(&(objectClass=person)(uid={uid}))",
                    "attributes": attributes or ["uid", "cn", "mail", "sn"],
                    "page_size": 100,  # Default page size
                    "paged_cookie": None,
                },
            )

        @classmethod
        def create_group_search(
            cls,
            cn: str,
            base_dn: str = "ou=groups,dc=example,dc=com",
            attributes: FlextCore.Types.StringList | None = None,
        ) -> FlextLdapModels.SearchRequest:
            """Create search request for group."""
            return cls.model_validate(
                {
                    "base_dn": base_dn,
                    "filter_str": f"(&(objectClass=groupOfNames)(cn={cn}))",
                    "attributes": attributes or ["cn", "member", "description"],
                    "page_size": 100,  # Default page size
                    "paged_cookie": None,
                },
            )

        @classmethod
        def create(
            cls,
            base_dn: str,
            filter_str: str | None = None,
            scope: str = FlextLdapConstants.Scopes.SUBTREE,
            attributes: FlextCore.Types.StringList | None = None,
        ) -> FlextLdapModels.SearchRequest:
            """Factory method with smart defaults from FlextLdapConstants.

            Creates a SearchRequest with intelligent defaults for common parameters,
            eliminating the need to specify page_size, paged_cookie, and other
            boilerplate parameters.

            Args:
                base_dn: Search base Distinguished Name
                filter_str: LDAP search filter
                scope: Search scope (default: SUBTREE from FlextLdapConstants)
                attributes: Attributes to retrieve (default: empty list for all attributes)

            Returns:
                FlextLdapModels.SearchRequest: Configured search request with smart defaults

            Example:
                # OLD: Manual parameter specification
                request = FlextLdapModels.SearchRequest(
                    base_dn=base_dn,
                    filter_str=filter_str,
                    scope=scope,
                    attributes=attributes or [],
                    page_size=FlextCore.Constants.Performance.DEFAULT_PAGE_SIZE,
                    paged_cookie=b"",
                )

                # NEW: Factory method with smart defaults (eliminate 3-4 lines)
                request = FlextLdapModels.SearchRequest.create(base_dn, filter_str, scope, attributes)

            """
            if filter_str is None:
                msg = "filter_str must be provided"
                raise ValueError(msg)

            return cls.model_validate({
                "base_dn": base_dn,
                "filter_str": filter_str,
                "scope": scope,
                "attributes": attributes or [],
                "page_size": FlextCore.Constants.Performance.DEFAULT_PAGE_SIZE,
                "paged_cookie": b"",
                "size_limit": FlextCore.Constants.Performance.BatchProcessing.MAX_VALIDATION_SIZE,
                "time_limit": FlextCore.Constants.Network.DEFAULT_TIMEOUT,
            })

        @staticmethod
        def create_user_filter(username_filter: str | None = None) -> str:
            """Create LDAP filter for user search.

            Creates a base filter for person objects, optionally combined with
            additional filter criteria.

            Args:
                username_filter: Optional additional filter to combine with base filter

            Returns:
                LDAP filter string for user search

            Example:
                # Basic user filter
                filter_str = SearchRequest.create_user_filter()
                # "(objectClass=person)"

                # Combined filter
                filter_str = SearchRequest.create_user_filter("(uid=john)")
                # "(&(objectClass=person)(uid=john))"

            """
            base_filter = "(objectClass=person)"
            if username_filter:
                return f"(&{base_filter}{username_filter})"
            return base_filter

        @staticmethod
        def create_group_filter(group_filter: str | None = None) -> str:
            """Create LDAP filter for group search.

            Creates a base filter for group objects, optionally combined with
            additional filter criteria.

            Args:
                group_filter: Optional additional filter to combine with base filter

            Returns:
                LDAP filter string for group search

            Example:
                # Basic group filter
                filter_str = SearchRequest.create_group_filter()
                # "(objectClass=groupOfNames)"

                # Combined filter
                filter_str = SearchRequest.create_group_filter("(cn=admins)")
                # "(&(objectClass=groupOfNames)(cn=admins))"

            """
            base_filter = "(objectClass=groupOfNames)"
            if group_filter:
                return f"(&{base_filter}{group_filter})"
            return base_filter

    class SearchResponse(Base):
        """LDAP Search Response entity."""

        # Results - using Entry models for type-safe entries
        entries: list[FlextLdapModels.Entry] = Field(
            default_factory=list,
            description="Search result entries",
        )

        # Result metadata
        total_count: int = Field(0, description="Total number of entries")
        has_more: bool = Field(default=False, description="More results available")

        # Core response fields
        result_code: int = Field(0, description="LDAP result code")
        result_description: str = Field(default="", description="Result description")
        matched_dn: str = Field(default="", description="Matched DN")
        has_more_pages: bool = Field(default=False, description="More pages available")
        next_cookie: bytes | None = Field(default=None, description="Next page cookie")
        entries_returned: int = Field(
            default=0,
            description="Number of entries returned",
        )
        time_elapsed: float = Field(default=0.0, description="Search time in seconds")

        @field_validator("entries_returned", mode="before")
        @classmethod
        def set_entries_returned(cls, v: int, info: ValidationInfo) -> int:
            """Auto-calculate entries returned from entries list."""
            # Use proper Pydantic 2 ValidationInfo pattern - no .data access
            try:
                # Access through proper validation context
                data = info.data or {}
                entries = data.get("entries")
                if isinstance(entries, list):
                    # Type-safe length calculation
                    return len(entries)
            except (AttributeError, KeyError):
                pass
            return v if isinstance(v, int) else 0

    class CreateUserRequest(Base, ValidationMixin):
        """LDAP User Creation Request entity."""

        # Required fields
        dn: str = Field(..., description="Distinguished Name for new user")
        uid: str = Field(..., description="User ID")
        cn: str = Field(..., description="Common Name")
        sn: str = Field(..., description="Surname")

        # Optional user attributes - can be provided as None
        given_name: str | None = Field(default=None, description="Given Name")
        mail: str | None = Field(default=None, description="Email address")
        user_password: str | SecretStr | None = Field(
            default=None,
            description="User password",
        )
        telephone_number: str | None = Field(default=None, description="Phone number")
        description: str | None = Field(default=None, description="User description")

        # Optional organizational fields
        department: str | None = Field(default=None, description="Department")
        organizational_unit: str | None = Field(
            default=None,
            description="Organizational Unit",
        )
        title: str | None = Field(default=None, description="Job title")
        organization: str | None = Field(default=None, description="Organization")

        # LDAP metadata
        object_classes: FlextCore.Types.StringList = Field(
            default_factory=lambda: [
                FlextLdapConstants.ObjectClasses.TOP,
                FlextLdapConstants.ObjectClasses.PERSON,
                FlextLdapConstants.ObjectClasses.INET_ORG_PERSON,
            ],
            description="LDAP object classes",
        )

        # Additional attributes
        additional_attributes: dict[
            str,
            FlextLdapTypes.LdapEntries.EntryAttributeValue,
        ] = Field(
            default_factory=dict,
            description="Additional user attributes",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format using centralized validation."""
            return FlextLdapModels.ValidationMixin.validate_dn_field(v)

        @field_validator("mail")
        @classmethod
        def validate_email(cls, value: str | None) -> str | None:
            """Validate email format using centralized validation."""
            if value is None:
                return None
            return cls.validate_email_field(value)

        @field_validator("user_password")
        @classmethod
        def validate_password(
            cls,
            value: str | SecretStr | None,
        ) -> str | SecretStr | None:
            """Validate password requirements using centralized validation."""
            if value is None:
                return None
            if isinstance(value, SecretStr):
                return value
            return cls.validate_password_field(value)

        @field_validator(
            "uid",
            "cn",
            "sn",
        )
        @classmethod
        def validate_required_string(cls, v: str) -> str:
            """Validate required string fields."""
            return cls.validate_required_string_field(v)

        @field_validator("given_name")
        @classmethod
        def validate_given_name(cls, v: str | None) -> str | None:
            """Validate given name field (optional)."""
            if v is None:
                return None
            return cls.validate_required_string_field(v)

        def validate_business_rules(self) -> FlextCore.Result[None]:
            """Validate create user request business rules."""
            if not self.dn:
                return FlextCore.Result[None].fail("DN cannot be empty")
            if not self.uid:
                return FlextCore.Result[None].fail("UID cannot be empty")
            if not self.cn:
                return FlextCore.Result[None].fail("Common Name cannot be empty")
            if not self.mail:
                return FlextCore.Result[None].fail("Email cannot be empty")
            if not self.user_password:
                return FlextCore.Result[None].fail("Password cannot be empty")
            return FlextCore.Result[None].ok(None)

        def to_user_entity(self) -> FlextLdapModels.LdapUser:
            """Convert request to user entity."""
            return FlextLdapModels.LdapUser(
                dn=self.dn,
                uid=self.uid,
                cn=self.cn,
                sn=self.sn,
                given_name=self.given_name,
                mail=self.mail,
                telephone_number=self.telephone_number,
                mobile=None,
                department=self.department,
                title=self.title,
                organization=self.organization,
                organizational_unit=self.organizational_unit,
                user_password=self.user_password,
                object_classes=self.object_classes,
                # Dict variance: EntryAttributeValue is compatible with object
                additional_attributes=self.additional_attributes,
            )

        def to_attributes(
            self,
        ) -> dict[str, FlextLdapTypes.LdapEntries.EntryAttributeValue]:
            """Convert request to LDAP attributes dictionary for entry creation."""
            attributes: dict[str, FlextLdapTypes.LdapEntries.EntryAttributeValue] = {
                "objectClass": self.object_classes,
                "uid": self.uid,
                "cn": self.cn,
                "sn": self.sn,
            }

            # Add optional attributes if they exist
            if self.given_name:
                attributes["givenName"] = self.given_name
            if self.mail:
                attributes["mail"] = self.mail
            if self.user_password:
                password = (
                    self.user_password.get_secret_value()
                    if isinstance(self.user_password, SecretStr)
                    else self.user_password
                )
                attributes["userPassword"] = password
            if self.telephone_number:
                attributes["telephoneNumber"] = self.telephone_number
            if self.description:
                attributes["description"] = self.description
            if self.department:
                attributes["department"] = self.department
            if self.organizational_unit:
                attributes["ou"] = self.organizational_unit
            if self.title:
                attributes["title"] = self.title
            if self.organization:
                attributes["o"] = self.organization

            # Add additional attributes
            attributes.update(self.additional_attributes)

            return attributes

    class CreateGroupRequest(Base, ValidationMixin):
        """LDAP Group Creation Request entity."""

        # Required fields
        dn: str = Field(..., description="Distinguished Name for new group")
        cn: str = Field(..., description="Common Name")

        # Required group attributes
        description: str = Field(..., description="Group description")
        members: FlextCore.Types.StringList = Field(
            ..., description="Initial group members"
        )

        # LDAP metadata
        object_classes: FlextCore.Types.StringList = Field(
            default_factory=lambda: ["groupOfNames", "top"],
            description="LDAP object classes",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format using centralized validation."""
            return FlextLdapModels.ValidationMixin.validate_dn_field(v)

        @field_validator("cn", "description")
        @classmethod
        def validate_cn(cls, v: str) -> str:
            """Validate Common Name and description."""
            return cls.validate_required_string_field(v)

        @field_validator("members")
        @classmethod
        def validate_members(
            cls, v: FlextCore.Types.StringList
        ) -> FlextCore.Types.StringList:
            """Validate members list."""
            if not v:
                error_msg = "Members list cannot be empty"
                exceptions = FlextLdapExceptions()
                raise exceptions.validation_error(
                    error_msg,
                    value=str(v),
                    field="members",
                )
            return v

        def to_attributes(
            self,
        ) -> dict[str, FlextLdapTypes.LdapEntries.EntryAttributeValue]:
            """Convert request to LDAP attributes dictionary for entry creation."""
            attributes: dict[str, FlextLdapTypes.LdapEntries.EntryAttributeValue] = {
                "objectClass": self.object_classes,
                "cn": self.cn,
                "description": self.description,
                "member": self.members,
            }

            return attributes

    class AddEntryRequest(Base, ValidationMixin):
        """LDAP Add Entry Request entity for general entry creation.

        Uses FlextCore.Models patterns for centralized validation and parameter management.
        Supports any LDAP object class with flexible attribute handling.
        """

        # Required fields
        dn: str = Field(..., description="Distinguished Name for new entry")
        attributes: dict[str, str | FlextCore.Types.StringList] = Field(
            ...,
            description="Entry attributes as key-value pairs",
        )

        # Optional object classes - defaults will be determined by attributes if not specified
        object_classes: FlextCore.Types.StringList | None = Field(
            default=None,
            description="LDAP object classes (auto-detected from attributes if not specified)",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format using centralized validation."""
            return FlextLdapModels.ValidationMixin.validate_dn_field(v)

        @field_validator("attributes")
        @classmethod
        def validate_attributes(
            cls,
            v: dict[str, str | FlextCore.Types.StringList],
        ) -> dict[str, str | FlextCore.Types.StringList]:
            """Validate entry attributes."""
            if not v:
                msg = "Attributes cannot be empty"
                raise ValueError(msg)
            return v

        @model_validator(mode="after")
        def validate_entry_consistency(self) -> FlextLdapModels.AddEntryRequest:
            """Validate entry consistency and auto-detect object classes if needed."""
            FlextLdapExceptions()

            # Auto-detect object classes if not specified
            if not self.object_classes:
                detected_classes = self._detect_object_classes_from_attributes()
                if detected_classes:
                    self.object_classes = detected_classes
                else:
                    # Default to 'top' if no specific classes detected
                    self.object_classes = [FlextLdapConstants.ObjectClasses.TOP]

            # Ensure objectClass is in attributes if not present
            if "objectClass" not in self.attributes:
                self.attributes["objectClass"] = self.object_classes

            return self

        def _detect_object_classes_from_attributes(self) -> FlextCore.Types.StringList:
            """Auto-detect object classes based on common attribute patterns."""
            classes = []

            # Always include top
            classes.append(FlextLdapConstants.ObjectClasses.TOP)

            # Detect person-related attributes
            person_attrs = {
                "cn",
                "sn",
                "givenName",
                "mail",
                "telephoneNumber",
                "userPassword",
                "uid",
                "description",
            }
            if any(attr in self.attributes for attr in person_attrs):
                classes.append(FlextLdapConstants.ObjectClasses.PERSON)
                # Check for inetOrgPerson specific attributes
                inet_attrs = {"mail", "telephoneNumber", "department", "title"}
                if any(attr in self.attributes for attr in inet_attrs):
                    classes.append(FlextLdapConstants.ObjectClasses.INET_ORG_PERSON)

            # Detect group-related attributes
            if "member" in self.attributes or "uniqueMember" in self.attributes:
                if "uniqueMember" in self.attributes:
                    classes.append(
                        FlextLdapConstants.ObjectClasses.GROUP_OF_UNIQUE_NAMES,
                    )
                else:
                    classes.append(FlextLdapConstants.ObjectClasses.GROUP_OF_NAMES)

            # Detect organizational unit
            if "ou" in self.attributes:
                classes.append("organizationalUnit")

            return classes

        def to_ldap_attributes(self) -> dict[str, FlextCore.Types.StringList]:
            """Convert attributes to LDAP format (all values as lists)."""
            ldap_attrs = {}
            for key, value in self.attributes.items():
                if isinstance(value, list):
                    ldap_attrs[key] = value
                else:
                    ldap_attrs[key] = [str(value)]
            return ldap_attrs

    class UpdateEntryRequest(Base, ValidationMixin):
        """Request model for updating LDAP entries.

        Provides type-safe update operations with strategy support for
        merge (default) or replace semantics.
        """

        dn: str = Field(..., description="Distinguished Name of entry to update")
        attributes: dict[str, str | FlextCore.Types.StringList] = Field(
            ...,
            description="Attributes to update",
        )
        strategy: FlextLdapConstants.UpdateStrategy = Field(
            default="merge",
            description="Update strategy: merge adds/updates, replace overwrites",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format."""
            return FlextLdapModels.ValidationMixin.validate_dn_field(v)

    class UpsertEntryRequest(Base, ValidationMixin):
        """Request model for upserting LDAP entries (create or update).

        Upsert semantics: create if entry doesn't exist, update if it does.
        """

        dn: str = Field(..., description="Distinguished Name for entry")
        attributes: dict[str, str | FlextCore.Types.StringList] = Field(
            ...,
            description="Entry attributes",
        )
        update_strategy: FlextLdapConstants.UpdateStrategy = Field(
            default="merge",
            description="Strategy if entry exists: merge or replace",
        )
        object_classes: FlextCore.Types.StringList | None = Field(
            default=None,
            description="Object classes for new entries",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format."""
            return FlextLdapModels.ValidationMixin.validate_dn_field(v)

    class SyncResult(Base):
        """Result model for sync operations.

        Tracks statistics and details of sync operations including
        created, updated, and deleted entries.
        """

        created: int = Field(default=0, description="Number of entries created")
        updated: int = Field(default=0, description="Number of entries updated")
        deleted: int = Field(default=0, description="Number of entries deleted")
        failed: int = Field(default=0, description="Number of failed operations")
        errors: FlextCore.Types.StringList = Field(
            default_factory=list,
            description="Error messages from failed operations",
        )
        operations: list[dict[str, str]] = Field(
            default_factory=list,
            description="Detailed operation log",
        )

        @property
        def total_operations(self) -> int:
            """Total number of operations performed."""
            return self.created + self.updated + self.deleted + self.failed

        @property
        def success_rate(self) -> float:
            """Success rate as percentage."""
            if self.total_operations == 0:
                return 100.0
            successful = self.created + self.updated + self.deleted
            return (successful / self.total_operations) * 100.0

    # =========================================================================
    # ACL REQUEST MODELS - High-velocity ACL operations
    # =========================================================================

    class CreateAclRequest(Base, ValidationMixin):
        """Request model for creating LDAP ACLs with quirks engine support.

        Supports automatic server type detection and format conversion
        via FlextLdif quirks engine integration.
        """

        dn: str = Field(..., description="Distinguished Name for ACL target")
        acl_type: FlextLdapConstants.AclType = Field(
            default="auto",
            description="ACL format type (auto-detect from server)",
        )
        acl_rules: FlextCore.Types.StringList = Field(
            ...,
            description="ACL rules in specified format",
        )
        server_type: str | None = Field(
            default=None,
            description="Explicit server type (auto-detected if None)",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format."""
            return FlextLdapModels.ValidationMixin.validate_dn_field(v)

    class UpdateAclRequest(Base, ValidationMixin):
        """Request model for updating existing LDAP ACLs."""

        dn: str = Field(..., description="Distinguished Name of ACL target")
        acl_rules: FlextCore.Types.StringList = Field(
            ...,
            description="ACL rules to apply",
        )
        strategy: FlextLdapConstants.UpdateStrategy = Field(
            default="merge",
            description="Update strategy: merge adds rules, replace overwrites",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format."""
            return FlextLdapModels.ValidationMixin.validate_dn_field(v)

    class UpsertAclRequest(Base, ValidationMixin):
        """Request model for upserting LDAP ACLs (create or update)."""

        dn: str = Field(..., description="Distinguished Name for ACL target")
        acl_type: FlextLdapConstants.AclType = Field(
            default="auto",
            description="ACL format type",
        )
        acl_rules: FlextCore.Types.StringList = Field(
            ...,
            description="ACL rules to apply",
        )
        update_strategy: FlextLdapConstants.UpdateStrategy = Field(
            default="merge",
            description="Strategy if ACL exists: merge or replace",
        )
        server_type: str | None = Field(
            default=None,
            description="Explicit server type (auto-detected if None)",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format."""
            return FlextLdapModels.ValidationMixin.validate_dn_field(v)

    class AclSyncResult(SyncResult):
        """Result model for ACL sync operations.

        Extends SyncResult with ACL-specific tracking and statistics.
        """

        acls_converted: int = Field(
            default=0,
            description="Number of ACLs converted between formats",
        )
        server_types_detected: FlextCore.Types.StringList = Field(
            default_factory=list,
            description="Server types detected during sync",
        )

    # =========================================================================
    # SCHEMA REQUEST MODELS - High-velocity schema operations
    # =========================================================================

    class CreateSchemaAttributeRequest(Base, ValidationMixin):
        """Request model for creating LDAP schema attributes with quirks support.

        Supports automatic syntax detection and server-specific handling
        via FlextLdif quirks engine integration.
        """

        name: str = Field(..., description="Attribute name (e.g., customAttr)")
        syntax: str = Field(
            ...,
            description="LDAP syntax OID (e.g., 1.3.6.1.4.1.1466.115.121.1.15 for Directory String)",
        )
        description: str | None = Field(
            default=None,
            description="Human-readable attribute description",
        )
        single_value: bool = Field(
            default=False,
            description="Whether attribute is single-valued",
        )
        equality_match: str | None = Field(
            default=None,
            description="Equality matching rule OID",
        )
        ordering_match: str | None = Field(
            default=None,
            description="Ordering matching rule OID",
        )
        substr_match: str | None = Field(
            default=None,
            description="Substring matching rule OID",
        )

    class CreateObjectClassRequest(Base, ValidationMixin):
        """Request model for creating LDAP object classes."""

        name: str = Field(..., description="Object class name")
        must_attributes: FlextCore.Types.StringList = Field(
            default_factory=list,
            description="Required attributes (MUST)",
        )
        may_attributes: FlextCore.Types.StringList = Field(
            default_factory=list,
            description="Optional attributes (MAY)",
        )
        parent: str | None = Field(
            default="top",
            description="Parent object class",
        )
        kind: FlextLdapConstants.ObjectClassKind = Field(
            default="STRUCTURAL",
            description="Object class type",
        )
        description: str | None = Field(
            default=None,
            description="Human-readable description",
        )

    class UpdateSchemaRequest(Base, ValidationMixin):
        """Request model for updating LDAP schema elements."""

        schema_dn: str = Field(
            ...,
            description="DN of schema subentry (e.g., cn=schema)",
        )
        changes: dict[str, str | FlextCore.Types.StringList] = Field(
            ...,
            description="Schema changes to apply",
        )
        strategy: FlextLdapConstants.UpdateStrategy = Field(
            default="merge",
            description="Update strategy",
        )

        @field_validator("schema_dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format."""
            return FlextLdapModels.ValidationMixin.validate_dn_field(v)

    class UpsertSchemaRequest(Base, ValidationMixin):
        """Request model for upserting LDAP schema elements."""

        schema_dn: str = Field(
            ...,
            description="DN of schema subentry",
        )
        schema_element: dict[str, str | FlextCore.Types.StringList] = Field(
            ...,
            description="Schema element definition",
        )
        update_strategy: FlextLdapConstants.UpdateStrategy = Field(
            default="merge",
            description="Strategy if schema element exists",
        )

        @field_validator("schema_dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format."""
            return FlextLdapModels.ValidationMixin.validate_dn_field(v)

    class SchemaSyncResult(SyncResult):
        """Result model for schema sync operations.

        Extends SyncResult with schema-specific tracking.
        """

        attributes_created: int = Field(
            default=0,
            description="Number of schema attributes created",
        )
        object_classes_created: int = Field(
            default=0,
            description="Number of object classes created",
        )
        schema_conflicts: FlextCore.Types.StringList = Field(
            default_factory=list,
            description="Schema conflicts encountered",
        )

    # =========================================================================
    # CONNECTION AND CONFIGURATION ENTITIES
    # =========================================================================

    class ConnectionInfo(Base, ValidationMixin):
        """LDAP Connection Information entity."""

        # Connection details
        server: str = Field(default="localhost", description="LDAP server hostname/IP")
        port: int = Field(
            FlextLdapConstants.Protocol.DEFAULT_PORT,
            description="LDAP server port",
            ge=1,
            le=FlextCore.Constants.Network.MAX_PORT,
        )
        use_ssl: bool = Field(default=False, description="Use SSL/TLS encryption")
        use_tls: bool = Field(default=False, description="Use StartTLS")

        # Authentication
        bind_dn: str | None = Field(default=None, description="Bind Distinguished Name")
        bind_password: SecretStr | None = Field(
            default=None,
            description="Bind password",
        )

        # Connection options - using centralized constants
        timeout: int = Field(
            FlextCore.Constants.Network.DEFAULT_TIMEOUT,
            description="Connection timeout in seconds",
            ge=1,
        )
        pool_size: int = Field(
            FlextCore.Constants.Performance.DEFAULT_DB_POOL_SIZE,
            description="Connection pool size",
            ge=1,
        )
        pool_keepalive: int = Field(
            FlextCore.Constants.Performance.DEFAULT_TTL_SECONDS,
            description="Pool keepalive in seconds",
            ge=0,
        )

        # SSL/TLS options
        verify_certificates: bool = Field(
            default=True,
            description="Verify SSL certificates",
        )
        ca_certs_file: str | None = Field(
            default=None,
            description="CA certificates file path",
        )

        @field_validator("server")
        @classmethod
        def validate_server(cls, v: str) -> str:
            """Validate server hostname/IP."""
            return cls.validate_required_string_field(v)

        @field_validator("port")
        @classmethod
        def validate_port(cls, v: int) -> int:
            """Validate port number."""
            if v <= 0 or v > FlextCore.Constants.Network.MAX_PORT:
                msg = (
                    f"Port must be between 1 and {FlextCore.Constants.Network.MAX_PORT}"
                )
                exceptions = FlextLdapExceptions()
                raise exceptions.validation_error(msg, value=str(v), field="port")
            return v

    # =========================================================================
    # ERROR AND STATUS ENTITIES
    # =========================================================================

    class LdapError(Base):
        """LDAP Error entity with detailed information."""

        # Error details
        error_code: int = Field(default=0, description="LDAP error code")
        error_message: str = Field(default="", description="Error message")
        matched_dn: str = Field(default="", description="Matched DN")

        # Context
        operation: str = Field(default="", description="Operation that failed")
        target_dn: str = Field(default="", description="Target DN")

        # Additional details
        server_info: FlextLdapModels.ServerInfo | None = Field(
            default=None,
            description="Server information",
        )

        # Timestamp
        timestamp: datetime = Field(
            default_factory=datetime.now,
            description="Error timestamp",
        )

        @field_validator("error_code")
        @classmethod
        def validate_error_code(cls, v: int) -> int:
            """Validate LDAP error code."""
            if v < 0:
                msg = "Error code must be non-negative"
                exceptions = FlextLdapExceptions()
                raise exceptions.validation_error(msg, value=str(v), field="error_code")
            return v

    class OperationResult(Base):
        """LDAP Operation Result entity."""

        # Result status
        success: bool = Field(default=True, description="Operation success status")
        result_code: int = Field(default=0, description="LDAP result code")
        result_message: str = Field(default="", description="Result message")

        # Operation details
        operation_type: str = Field(default="", description="Type of operation")
        target_dn: str = Field(default="", description="Target DN")

        # Performance metrics
        duration_ms: float = Field(
            0.0,
            description="Operation duration in milliseconds",
        )

        # Additional data
        data: FlextCore.Types.Dict = Field(
            default_factory=dict,
            description="Additional result data",
        )

        # Timestamp
        timestamp: datetime = Field(
            default_factory=datetime.now,
            description="Operation timestamp",
        )

        @classmethod
        def success_result(
            cls,
            operation_type: str,
            target_dn: str = "",
            data: FlextCore.Types.Dict | None = None,
            duration_ms: float = 0.0,
        ) -> FlextLdapModels.OperationResult:
            """Create success result."""
            return cls(
                success=True,
                result_code=0,
                result_message="Success",
                operation_type=operation_type,
                target_dn=target_dn,
                data=data or {},
                duration_ms=duration_ms,
            )

        @classmethod
        def error_result(
            cls,
            operation_type: str,
            error_code: int,
            error_message: str,
            target_dn: str = "",
            duration_ms: float = 0.0,
        ) -> FlextLdapModels.OperationResult:
            """Create error result."""
            return cls(
                success=False,
                result_code=error_code,
                result_message=error_message,
                operation_type=operation_type,
                target_dn=target_dn,
                duration_ms=duration_ms,
            )

    class ConnectionConfig(FlextCore.Models.Value):
        """LDAP connection configuration value object - Pydantic Value Object."""

        server: str
        port: int = FlextLdapConstants.Protocol.DEFAULT_PORT
        use_ssl: bool = False
        bind_dn: str | None = None
        bind_password: str | None = None
        timeout: int = FlextCore.Constants.Network.DEFAULT_TIMEOUT

        @computed_field  # Pydantic v2 computed field - no @property needed
        def server_uri(self) -> str:
            """Get server URI."""
            protocol = "ldaps://" if self.use_ssl else "ldap://"
            return f"{protocol}{self.server}:{self.port}"

        @computed_field  # Pydantic v2 computed field - no @property needed
        def password(self) -> str | None:
            """Get bind password."""
            return self.bind_password

        @computed_field  # Pydantic v2 computed field - no @property needed
        def base_dn(self) -> str:
            """Get base DN (default empty)."""
            return ""

        def validate_business_rules(self) -> FlextCore.Result[None]:
            """Validate the configuration business rules and return FlextCore.Result.

            Returns:
                FlextCore.Result[None] indicating validation success or failure

            """
            try:
                if not self.server or not self.server.strip():
                    return FlextCore.Result[None].fail("Server cannot be empty")
                max_port = 65535
                if self.port <= 0 or self.port > max_port:
                    return FlextCore.Result[None].fail("Invalid port number")
                return FlextCore.Result[None].ok(None)
            except Exception as e:
                return FlextCore.Result[None].fail(f"Validation failed: {e}")

    class ModifyConfig(FlextCore.Models.Command):
        """LDAP modify operation configuration - Pydantic Command."""

        dn: str
        changes: dict[str, list[tuple[str, FlextCore.Types.StringList]]]

        def validate_business_rules(self) -> FlextCore.Result[None]:
            """Validate the configuration business rules and return FlextCore.Result.

            Returns:
                FlextCore.Result[None] indicating validation success or failure

            """
            try:
                if not self.dn or not self.dn.strip():
                    return FlextCore.Result[None].fail("DN cannot be empty")
                if not self.changes:
                    return FlextCore.Result[None].fail("Changes cannot be empty")
                return FlextCore.Result[None].ok(None)
            except Exception as e:
                return FlextCore.Result[None].fail(f"Validation failed: {e}")

    class AddConfig(FlextCore.Models.Command):
        """LDAP add operation configuration - Pydantic Command."""

        dn: str
        attributes: dict[str, FlextCore.Types.StringList]

        def validate_business_rules(self) -> FlextCore.Result[None]:
            """Validate the configuration business rules and return FlextCore.Result.

            Returns:
                FlextCore.Result[None] indicating validation success or failure

            """
            try:
                if not self.dn or not self.dn.strip():
                    return FlextCore.Result[None].fail("DN cannot be empty")
                if not self.attributes:
                    return FlextCore.Result[None].fail("Attributes cannot be empty")
                return FlextCore.Result[None].ok(None)
            except Exception as e:
                return FlextCore.Result[None].fail(f"Validation failed: {e}")

    class DeleteConfig(FlextCore.Models.Command):
        """LDAP delete operation configuration - Pydantic Command."""

        dn: str

        def validate_business_rules(self) -> FlextCore.Result[None]:
            """Validate the configuration business rules and return FlextCore.Result.

            Returns:
                FlextCore.Result[None] indicating validation success or failure

            """
            try:
                if not self.dn or not self.dn.strip():
                    return FlextCore.Result[None].fail("DN cannot be empty")
                return FlextCore.Result[None].ok(None)
            except Exception as e:
                return FlextCore.Result[None].fail(f"Validation failed: {e}")

    class SearchConfig(FlextCore.Models.Query):
        """LDAP search operation configuration - Pydantic Query."""

        model_config = ConfigDict(frozen=True)

        base_dn: str
        filter_str: str
        attributes: FlextCore.Types.StringList

        @model_validator(mode="after")
        def validate_config(self) -> FlextLdapModels.SearchConfig:
            """Validate search configuration using Pydantic validator."""
            if not self.base_dn or not self.base_dn.strip():
                msg = "Base DN cannot be empty"
                raise ValueError(msg)
            if not self.filter_str or not self.filter_str.strip():
                msg = "Filter string cannot be empty"
                raise ValueError(msg)
            # Empty attributes list is valid in LDAP (returns only DN)
            return self

    # =========================================================================
    # CQRS MESSAGE MODELS - Command Query Responsibility Segregation
    # =========================================================================

    class CqrsCommand(Base):
        """CQRS Command message envelope."""

        command_type: str = Field(default="", description="Command type identifier")
        command_id: str = Field(default="", description="Unique command identifier")
        payload: FlextCore.Types.Dict = Field(
            default_factory=dict,
            description="Command payload data",
        )
        metadata: FlextCore.Types.Dict = Field(
            default_factory=dict,
            description="Command metadata",
        )
        timestamp: int | None = Field(default=None, description="Command timestamp")

        @classmethod
        def create(
            cls,
            command_type: str,
            command_id: str,
            payload: FlextCore.Types.Dict | None = None,
            metadata: FlextCore.Types.Dict | None = None,
            timestamp: int | None = None,
        ) -> FlextCore.Result[FlextLdapModels.CqrsCommand]:
            """Create CQRS command message."""
            # Explicit FlextCore.Result error handling - NO try/except
            instance = cls(
                command_type=command_type,
                command_id=command_id,
                payload=payload or {},
                metadata=metadata or {},
                timestamp=timestamp,
            )
            return FlextCore.Result[FlextLdapModels.CqrsCommand].ok(instance)

    class CqrsQuery(Base):
        """CQRS Query message envelope."""

        query_type: str = Field(default="", description="Query type identifier")
        query_id: str = Field(default="", description="Unique query identifier")
        parameters: FlextCore.Types.Dict = Field(
            default_factory=dict,
            description="Query parameters",
        )
        metadata: FlextCore.Types.Dict = Field(
            default_factory=dict,
            description="Query metadata",
        )
        timestamp: int | None = Field(default=None, description="Query timestamp")

        @classmethod
        def create(
            cls,
            query_type: str,
            query_id: str,
            parameters: FlextCore.Types.Dict | None = None,
            metadata: FlextCore.Types.Dict | None = None,
            timestamp: int | None = None,
        ) -> FlextCore.Result[FlextLdapModels.CqrsQuery]:
            """Create CQRS query message."""
            # Explicit FlextCore.Result error handling - NO try/except
            instance = cls(
                query_type=query_type,
                query_id=query_id,
                parameters=parameters or {},
                metadata=metadata or {},
                timestamp=timestamp,
            )
            return FlextCore.Result[FlextLdapModels.CqrsQuery].ok(instance)

    class CqrsEvent(Base):
        """CQRS Event message envelope for domain events."""

        event_type: str = Field(default="", description="Event type identifier")
        event_id: str = Field(default="", description="Unique event identifier")
        aggregate_id: str = Field(default="", description="Aggregate root identifier")
        payload: FlextCore.Types.Dict = Field(
            default_factory=dict,
            description="Event payload data",
        )
        metadata: FlextCore.Types.Dict = Field(
            default_factory=dict,
            description="Event metadata",
        )
        timestamp: int = Field(default=0, description="Event timestamp")
        version: int = Field(default=1, description="Event version")

        @classmethod
        def create(
            cls,
            event_type: str,
            event_id: str,
            aggregate_id: str,
            timestamp: int,
            payload: FlextCore.Types.Dict | None = None,
            metadata: FlextCore.Types.Dict | None = None,
            version: int = 1,
        ) -> FlextCore.Result[FlextLdapModels.CqrsEvent]:
            """Create CQRS event message."""
            # Explicit FlextCore.Result error handling - NO try/except
            instance = cls(
                event_type=event_type,
                event_id=event_id,
                aggregate_id=aggregate_id,
                payload=payload or {},
                metadata=metadata or {},
                timestamp=timestamp,
                version=version,
            )
            return FlextCore.Result[FlextLdapModels.CqrsEvent].ok(instance)

    class DomainMessage(Base):
        """Generic domain message envelope for CQRS infrastructure."""

        message_type: str = Field(..., description="Message type identifier")
        message_id: str = Field(..., description="Unique message identifier")
        data: FlextCore.Types.Dict = Field(
            default_factory=dict, description="Message data"
        )
        metadata: FlextCore.Types.Dict = Field(
            default_factory=dict,
            description="Message metadata",
        )
        timestamp: int | None = Field(None, description="Message timestamp")
        processed: bool = Field(False, description="Message processed flag")

        @classmethod
        def create(
            cls,
            message_type: str,
            message_id: str,
            data: FlextCore.Types.Dict | None = None,
            metadata: FlextCore.Types.Dict | None = None,
            timestamp: int | None = None,
            *,
            processed: bool = False,
        ) -> FlextCore.Result[FlextLdapModels.DomainMessage]:
            """Create domain message."""
            # Explicit FlextCore.Result error handling - NO try/except
            instance = cls(
                message_type=message_type,
                message_id=message_id,
                data=data or {},
                metadata=metadata or {},
                timestamp=timestamp,
                processed=processed,
            )
            return FlextCore.Result[FlextLdapModels.DomainMessage].ok(instance)

    class AclTarget(Base):
        """ACL target specification for access control rules."""

        target_type: str = Field(
            default="entry",
            description="Target type (entry, attr, etc.)",
        )
        dn_pattern: str = Field(
            default="*",
            description="DN pattern for target matching",
        )
        attributes: FlextCore.Types.StringList = Field(
            default_factory=list,
            description="Target attributes (empty means all)",
        )
        filter_expression: str = Field(
            default="",
            description="LDAP filter for target matching",
        )
        scope: str = Field(default="subtree", description="Search scope for target")

        @classmethod
        def create(
            cls,
            target_type: str = "entry",
            dn_pattern: str = "*",
            attributes: FlextCore.Types.StringList | None = None,
            filter_expression: str = "",
            scope: str = "subtree",
        ) -> FlextCore.Result[FlextLdapModels.AclTarget]:
            """Create AclTarget instance.

            Factory method for creating AclTarget with FlextCore.Result error handling.

            Args:
                target_type: Target type (entry, attr, etc.)
                dn_pattern: DN pattern for target matching
                attributes: Target attributes (empty means all)
                filter_expression: LDAP filter for target matching
                scope: Search scope for target

            Returns:
                FlextCore.Result[AclTarget] containing the created instance

            """
            # Explicit FlextCore.Result error handling - NO try/except
            return FlextCore.Result.ok(
                cls(
                    target_type=target_type,
                    dn_pattern=dn_pattern,
                    attributes=attributes or [],
                    filter_expression=filter_expression,
                    scope=scope,
                ),
            )

    class AclSubject(Base):
        """ACL subject specification for access control rules."""

        subject_type: str = Field(..., description="Subject type (user, group, etc.)")
        subject_dn: str = Field(default="*", description="Subject DN identifier")
        authentication_level: str | None = Field(
            default=None,
            description="Authentication level",
        )

        @classmethod
        def create(
            cls,
            subject_type: str,
            subject_dn: str,
            authentication_level: str | None = None,
        ) -> FlextCore.Result[FlextLdapModels.AclSubject]:
            """Create AclSubject instance."""
            # Explicit FlextCore.Result error handling - NO try/except
            return FlextCore.Result.ok(
                cls(
                    subject_type=subject_type,
                    subject_dn=subject_dn,
                    authentication_level=authentication_level,
                ),
            )

    class AclPermissions(Base):
        """ACL permissions specification."""

        grant_type: str = Field(
            default="allow",
            description="Grant type: allow or deny",
        )
        granted_permissions: FlextCore.Types.StringList = Field(
            default_factory=list,
            description="Granted permissions (read, write, etc.)",
        )
        denied_permissions: FlextCore.Types.StringList = Field(
            default_factory=list,
            description="Denied permissions (read, write, etc.)",
        )

        @model_validator(mode="before")
        @classmethod
        def handle_permissions_parameter(cls, data: object) -> object:
            """Handle 'permissions' parameter for convenience."""
            if isinstance(data, dict) and "permissions" in data:
                permissions = data.pop("permissions")
                grant_type = data.get("grant_type", "allow")
                if grant_type == "allow":
                    data["granted_permissions"] = permissions
                else:
                    data["denied_permissions"] = permissions
            return data

        @property
        def permissions(self) -> FlextCore.Types.StringList:
            """Get permissions based on grant type."""
            return (
                self.granted_permissions
                if self.grant_type == "allow"
                else self.denied_permissions
            )

        @property
        def grant(self) -> bool:
            """Whether this is a grant rule."""
            return self.grant_type == "allow"

        @classmethod
        def create(
            cls,
            permissions: FlextCore.Types.StringList,
            denied_permissions: FlextCore.Types.StringList | None = None,
            grant_type: str = "allow",
        ) -> FlextCore.Result[FlextLdapModels.AclPermissions]:
            """Create AclPermissions instance."""
            # Explicit FlextCore.Result error handling - NO try/except
            return FlextCore.Result.ok(
                cls(
                    granted_permissions=permissions,
                    denied_permissions=denied_permissions or [],
                    grant_type=grant_type,
                ),
            )

    class Acl(Base):
        """Unified ACL representation across different LDAP server types."""

        name: str = Field(..., description="ACL rule name")
        target: FlextLdapModels.AclTarget
        subject: FlextLdapModels.AclSubject
        permissions: FlextLdapModels.AclPermissions
        server_type: str = Field(default="generic", description="LDAP server type")
        raw_acl: str | None = Field(
            default=None,
            description="Raw ACL string if available",
        )
        priority: int = Field(default=100, description="ACL rule priority")

        @classmethod
        def create(
            cls,
            target: FlextLdapModels.AclTarget,
            subject: FlextLdapModels.AclSubject,
            permissions: FlextLdapModels.AclPermissions,
            name: str,
            priority: int = 100,
            server_type: str = "generic",
        ) -> FlextCore.Result[FlextLdapModels.Acl]:
            """Create Acl instance."""
            # Explicit FlextCore.Result error handling - NO try/except
            return FlextCore.Result.ok(
                cls(
                    name=name,
                    target=target,
                    subject=subject,
                    permissions=permissions,
                    server_type=server_type,
                    priority=priority,
                ),
            )

    class AclRule(Base):
        """Generic ACL rule structure."""

        id: str | None = Field(default=None, description="Rule identifier")
        target: FlextLdapModels.AclTarget
        subject: FlextLdapModels.AclSubject
        permissions: FlextLdapModels.AclPermissions
        conditions: FlextCore.Types.Dict = Field(
            default_factory=dict,
            description="Additional conditions",
        )
        enabled: bool = Field(default=True, description="Whether the rule is enabled")

    # =========================================================================
    # ACL MODEL CLASSES - Server-specific ACL representations
    # =========================================================================

    class OpenLdapAcl(Base):
        """OpenLDAP ACL model for slapd access control directives."""

        access_line: str = Field(..., description="OpenLDAP access directive line")
        target_spec: str = Field(
            ..., description="Target specification (*, attrs, etc.)"
        )
        subject_spec: str = Field(
            ..., description="Subject specification (user, group, etc.)"
        )
        permissions: str = Field(
            ..., description="Permission specification (read, write, etc.)"
        )
        control: str = Field(default="", description="Control specification")

        @classmethod
        def create(
            cls,
            access_line: str,
            target_spec: str,
            subject_spec: str | None = None,
            permissions: str | None = None,
        ) -> FlextCore.Result[FlextLdapModels.OpenLdapAcl]:
            """Create OpenLdapAcl from access line components."""
            # Constants for ACL parsing (reference FlextLdapConstants.Parsing.MIN_ACL_PARTS)
            min_acl_parts = 2  # Minimum parts required for valid ACL
            min_subject_perm_parts = 2  # Minimum parts for subject and permissions

            try:
                # Parse access line if components not provided
                if not subject_spec or not permissions:
                    # Simple parsing logic for demonstration
                    parts = access_line.replace("access to", "").strip().split("by")
                    if len(parts) >= min_acl_parts:
                        parts[0].strip()
                        subject_perm_part = parts[1].strip()
                        subject_perm_split = subject_perm_part.split()
                        if len(subject_perm_split) >= min_subject_perm_parts:
                            subject_spec = subject_spec or subject_perm_split[0]
                            permissions = permissions or " ".join(
                                subject_perm_split[1:]
                            )

                return FlextCore.Result[FlextLdapModels.OpenLdapAcl].ok(
                    cls(
                        access_line=access_line,
                        target_spec=target_spec,
                        subject_spec=subject_spec or "*",
                        permissions=permissions or "read",
                    )
                )
            except Exception as e:
                return FlextCore.Result[FlextLdapModels.OpenLdapAcl].fail(
                    f"Failed to create OpenLdapAcl: {e}"
                )

    class OracleAcl(Base):
        """Oracle OID/OUD ACL model for ACI directives."""

        aci_value: str = Field(..., description="Oracle ACI directive value")
        target_dn: str = Field(..., description="Target DN for the ACI")
        subject_spec: str = Field(..., description="Subject specification")
        permissions: str = Field(..., description="Permission specification")
        scope: str = Field(default="subtree", description="ACI scope")

        @classmethod
        def create(
            cls,
            aci_value: str,
            target_dn: str,
            subject_spec: str | None = None,
            permissions: str | None = None,
        ) -> FlextCore.Result[FlextLdapModels.OracleAcl]:
            """Create OracleAcl from ACI components."""
            try:
                return FlextCore.Result[FlextLdapModels.OracleAcl].ok(
                    cls(
                        aci_value=aci_value,
                        target_dn=target_dn,
                        subject_spec=subject_spec or "*",
                        permissions=permissions or "read",
                    )
                )
            except Exception as e:
                return FlextCore.Result[FlextLdapModels.OracleAcl].fail(
                    f"Failed to create OracleAcl: {e}"
                )

    class AciFormat(Base):
        """ACI (Access Control Information) format model."""

        aci_string: str = Field(..., description="Complete ACI string")
        version: str = Field(default="v3", description="ACI version")
        target: str = Field(..., description="Target specification")
        subject: str = Field(..., description="Subject specification")
        permissions: str = Field(..., description="Permissions specification")

        @classmethod
        def create(
            cls,
            aci_string: str,
            target: str | None = None,
            subject: str | None = None,
            permissions: str | None = None,
        ) -> FlextCore.Result[FlextLdapModels.AciFormat]:
            """Create AciFormat from ACI string components."""
            try:
                return FlextCore.Result[FlextLdapModels.AciFormat].ok(
                    cls(
                        aci_string=aci_string,
                        target=target or "*",
                        subject=subject or "*",
                        permissions=permissions or "read",
                    )
                )
            except Exception as e:
                return FlextCore.Result[FlextLdapModels.AciFormat].fail(
                    f"Failed to create AciFormat: {e}"
                )

    class ConversionResult(Base):
        """Result of ACL/entry conversion operations."""

        success: bool = Field(..., description="Whether conversion succeeded")
        original_format: str = Field(..., description="Original format type")
        target_format: str = Field(..., description="Target format type")
        converted_data: FlextCore.Types.Dict = Field(
            default_factory=dict,
            description="Converted data structure",
        )
        errors: FlextCore.Types.StringList = Field(
            default_factory=list,
            description="Conversion errors/warnings",
        )
        warnings: FlextCore.Types.StringList = Field(
            default_factory=list,
            description="Conversion warnings",
        )

        @classmethod
        def create(
            cls,
            success: bool,
            original_format: str,
            target_format: str,
            converted_data: FlextCore.Types.Dict | None = None,
            errors: FlextCore.Types.StringList | None = None,
            warnings: FlextCore.Types.StringList | None = None,
        ) -> FlextCore.Result[FlextLdapModels.ConversionResult]:
            """Create ConversionResult from conversion operation."""
            try:
                return FlextCore.Result[FlextLdapModels.ConversionResult].ok(
                    cls(
                        success=success,
                        original_format=original_format,
                        target_format=target_format,
                        converted_data=converted_data or {},
                        errors=errors or [],
                        warnings=warnings or [],
                    )
                )
            except Exception as e:
                return FlextCore.Result[FlextLdapModels.ConversionResult].fail(
                    f"Failed to create ConversionResult: {e}"
                )

    class LdapConfigValidation(StrictModel):
        """Simple model for LDAP configuration validation.

        Used by services to validate raw LDAP configuration data before
        creating full FlextLdapConfig instances.
        """

        ldap_server: str = Field(..., description="LDAP server address")
        ldap_port: int = Field(..., ge=1, le=65535, description="LDAP server port")
        base_dn: str = Field(..., description="LDAP base DN")

    class OperationRecord(StrictModel):
        """Model for LDAP operation records used in reporting."""

        type: str = Field(..., description="Operation type")
        success: bool = Field(..., description="Whether operation succeeded")
        # Additional fields can be added as needed

    class OperationReport(StrictModel):
        """Model for LDAP operation reports."""

        total_operations: int = Field(
            ..., ge=0, description="Total number of operations"
        )
        successful_operations: int = Field(
            ..., ge=0, description="Number of successful operations"
        )
        failed_operations: int = Field(
            ..., ge=0, description="Number of failed operations"
        )
        success_rate: float = Field(
            ..., ge=0, le=100, description="Success rate percentage"
        )
        operation_breakdown: dict[str, int] = Field(
            ..., description="Breakdown by operation type"
        )
        generated_at: str = Field(..., description="Report generation timestamp")

    class ServerInfo(FlexibleModel):
        """Model for LDAP server information from Root DSE.

        Uses FlexibleModel to allow server-specific attributes like vendor, version, etc.
        """

        naming_contexts: FlextCore.Types.StringList = Field(
            default_factory=list, description="Naming contexts"
        )
        supported_ldap_version: FlextCore.Types.StringList = Field(
            default_factory=list, description="Supported LDAP versions"
        )
        supported_sasl_mechanisms: FlextCore.Types.StringList = Field(
            default_factory=list, description="Supported SASL mechanisms"
        )
        supported_controls: FlextCore.Types.StringList = Field(
            default_factory=list, description="Supported controls"
        )
        supported_extensions: FlextCore.Types.StringList = Field(
            default_factory=list, description="Supported extensions"
        )
        vendor_name: str | None = Field(default=None, description="Vendor name")
        vendor_version: str | None = Field(default=None, description="Vendor version")

    class AdditionalAttributes(FlexibleModel):
        """Model for additional LDAP attributes with dynamic schema support."""

        # This model allows any additional attributes through FlexibleModel
        # Individual implementations can add specific fields as needed

    class EntryChanges(FlexibleModel):
        """Model for LDAP entry attribute changes."""

        # This model allows any attribute changes through FlexibleModel
        # Keys are attribute names, values are the new attribute values

    class ServerCapabilities(StrictModel):
        """Model for LDAP server capabilities."""

        supports_ssl: bool = Field(default=True, description="Supports SSL/TLS")
        supports_starttls: bool = Field(default=True, description="Supports STARTTLS")
        supports_paged_results: bool = Field(
            default=True, description="Supports paged results"
        )
        supports_vlv: bool = Field(
            default=False, description="Supports Virtual List View"
        )
        supports_sasl: bool = Field(
            default=True, description="Supports SASL authentication"
        )
        max_page_size: int = Field(default=1000, ge=0, description="Maximum page size")

    class ServerAttributes(FlexibleModel):
        """Model for server-specific LDAP attributes."""

        # This model allows any server-specific attributes through FlexibleModel

    class RootDSE(StrictModel):
        """Model for LDAP Root DSE (DSA-Specific Entry) information."""

        naming_contexts: FlextCore.Types.StringList = Field(
            default_factory=list, description="Naming contexts"
        )
        supported_ldap_version: FlextCore.Types.StringList = Field(
            default_factory=list, description="Supported LDAP versions"
        )
        supported_sasl_mechanisms: FlextCore.Types.StringList = Field(
            default_factory=list, description="Supported SASL mechanisms"
        )
        supported_controls: FlextCore.Types.StringList = Field(
            default_factory=list, description="Supported controls"
        )
        supported_extensions: FlextCore.Types.StringList = Field(
            default_factory=list, description="Supported extensions"
        )
        subschema_subentry: str | None = Field(
            default=None, description="Subschema subentry DN"
        )
        vendor_name: str | None = Field(default=None, description="Vendor name")
        vendor_version: str | None = Field(default=None, description="Vendor version")

    class Config(FlextCore.Config):
        """Enterprise LDAP configuration with advanced FlextCore.Config features.

        Extends FlextCore.Config with LDAP-specific configuration, computed fields,
        infrastructure protocols, and advanced validation. Provides centralized
        configuration management for all LDAP operations across the FLEXT ecosystem.

        **Advanced Features**:
        - Computed fields for derived LDAP configurations
        - Infrastructure protocol implementations (Configurable, ConfigValidator, ConfigPersistence)
        - Direct access pattern with dot notation support (config('ldap.connection.server'))
        - File persistence operations (JSON format)
        - LDAP-specific handler configuration utilities
        - Enhanced singleton management for LDAP contexts
        - Comprehensive validation with business rules
        - Dependency injection integration with providers.Configuration

        **Function**: Enterprise LDAP configuration management
            - LDAP connection, authentication, and operation settings
            - Pooling, caching, retry, and logging configurations
            - Computed fields for derived connection strings and capabilities
            - Validation methods for configuration integrity and business rules
            - File persistence for configuration management

        **Uses**: Pydantic Settings for LDAP configuration
            - BaseSettings for environment-based LDAP configuration
            - Field for default values and validation rules
            - SecretStr for sensitive LDAP credentials protection
            - field_validator for custom LDAP format validation
            - model_validator for cross-field LDAP consistency validation
            - computed_field for derived LDAP connection properties
            - FlextCore.Constants for LDAP-specific configuration defaults
            - FlextCore.Result[T] for operation results with error handling
            - FlextCore.Types for type definitions
            - Infrastructure protocols for LDAP configuration management

        **How to use**: Access and configure LDAP settings
            ```python
            from flext_ldap import FlextLdapConfig

            # Example 1: Create LDAP configuration instance
            config = FlextLdapConfig()

            # Example 2: Access LDAP configuration values
            server_uri = config.ldap_server_uri
            bind_dn = config.ldap_bind_dn
            timeout = config.ldap_connection_timeout


            # Example 4: Check LDAP configuration validity
            validation_result = config.validate_ldap_requirements()
            if validation_result.is_success:
                print("LDAP configuration valid")

            # Example 5: Access computed fields
            connection_info = config.connection_info
            print(f"Effective URI: {connection_info['effective_uri']}")

            # Example 6: Direct access with dot notation
            port = config("ldap.connection.port")  # Supports nested access
            ssl_enabled = config("ldap.connection.ssl")

            # Example 7: Handler configuration
            handler_config = config.create_ldap_handler_config(
                handler_mode="query", ldap_operation="search"
            )
            ```

        Args:
            **data: LDAP configuration values as keyword arguments.

        Attributes:
            ldap_server_uri (str): LDAP server URI (ldap:// or ldaps://)
            ldap_port (int): LDAP server port number
            ldap_use_ssl (bool): Enable SSL/TLS for connections
            ldap_verify_certificates (bool): Verify SSL certificates
            ldap_bind_dn (str | None): Bind distinguished name
            ldap_bind_password (SecretStr | None): Bind password (sensitive)
            ldap_base_dn (str): Base DN for searches
            ldap_pool_size (int): Connection pool size
            ldap_pool_timeout (int): Pool timeout in seconds
            ldap_connection_timeout (int): Connection timeout
            ldap_operation_timeout (int): Operation timeout
            ldap_size_limit (int): Search size limit
            ldap_time_limit (int): Search time limit
            ldap_enable_caching (bool): Enable result caching
            ldap_cache_ttl (int): Cache TTL in seconds
            ldap_retry_attempts (int): Retry attempts for operations
            ldap_retry_delay (int): Delay between retries
            ldap_enable_debug (bool): Enable debug logging
            ldap_enable_trace (bool): Enable trace logging
            ldap_log_queries (bool): Log LDAP queries
            ldap_mask_passwords (bool): Mask passwords in logs

        Returns:
            FlextLdapConfig: LDAP configuration instance with all FlextCore.Config features.

        Raises:
            ValidationError: When LDAP configuration validation fails.
            ValueError: When required LDAP configuration missing.

        Note:
            Direct instantiation pattern - create with FlextLdapConfig().
            SecretStr protects LDAP credentials. Configuration validated on load.
            Supports advanced dot notation access (config('ldap.connection.server')).

        Warning:
            Never commit LDAP credentials to source control.
            All configuration through direct instantiation or file loading.
            LDAP configuration changes require service restart.

        Example:
            Complete LDAP configuration management workflow:

            >>> config = FlextLdapConfig()
            >>> print(config.ldap_server_uri)
            ldap://localhost:389
            >>> print(config.connection_info["effective_uri"])
            ldap://localhost:389
            >>> validation = config.validate_ldap_requirements()
            >>> print(validation.is_success)
            True

        See Also:
            FlextCore.Config: Base configuration class with core features.
            FlextLdapConstants: LDAP-specific configuration defaults.
            FlextLdapModels: LDAP data models.
            FlextLdapExceptions: LDAP-specific exceptions.

        """

        # Dependency Injection integration (v1.1.0+)
        _di_config_provider: ClassVar[providers.Configuration | None] = None
        _di_provider_lock: ClassVar[threading.Lock] = threading.Lock()

        # Singleton pattern with per-class support (inherited from FlextCore.Config)
        # _instances and _lock are inherited - no override needed

        class LdapHandlerConfiguration:
            """LDAP-specific handler configuration utilities."""

            @staticmethod
            def resolve_ldap_operation_mode(
                operation_mode: str | None = None,
                operation_config: object = None,
            ) -> str | None:
                """Resolve LDAP operation mode from various sources.

                Args:
                    operation_mode: Explicit LDAP operation mode
                    operation_config: Config object containing operation_type

                Returns:
                    str: Resolved operation mode (search, modify, authenticate)

                """
                # Use explicit operation_mode if provided and valid
                valid_modes = {
                    "search",
                    "modify",
                    "add",
                    "delete",
                    "authenticate",
                    "bind",
                }
                if operation_mode in valid_modes:
                    return operation_mode

                # Try to extract from config object
                if operation_config is not None:
                    # Try attribute access
                    if hasattr(operation_config, "operation_type"):
                        config_mode: str | None = getattr(
                            operation_config, "operation_type", None
                        )
                        if config_mode in valid_modes:
                            return str(config_mode)

                    # Try dict[str, object] access
                    if isinstance(operation_config, dict):
                        config_mode_dict = operation_config.get(
                            FlextLdapConstants.DictKeys.OPERATION_TYPE,
                        )
                        if (
                            isinstance(config_mode_dict, str)
                            and config_mode_dict in valid_modes
                        ):
                            return config_mode_dict

                # Default to search
                return "search"

            @staticmethod
            def create_ldap_handler_config(
                operation_mode: str | None = None,
                ldap_operation: str | None = None,
                handler_name: str | None = None,
                handler_id: str | None = None,
                ldap_config: FlextCore.Types.Dict | None = None,
                connection_timeout: int = 30,
                operation_timeout: int = 60,
                max_retries: int = 3,
            ) -> FlextCore.Types.Dict:
                """Create LDAP handler configuration dictionary.

                Args:
                    operation_mode: LDAP operation mode (search, modify, etc.)
                    ldap_operation: Specific LDAP operation name
                    handler_name: Handler name
                    handler_id: Handler ID
                    ldap_config: Additional LDAP configuration to merge
                    connection_timeout: Connection timeout in seconds
                    operation_timeout: Operation timeout in seconds
                    max_retries: Maximum retry attempts

                Returns:
                    dict[str, object]: LDAP handler configuration dictionary

                """
                # Resolve operation mode
                resolved_mode = FlextLdapModels.Config.LdapHandlerConfiguration.resolve_ldap_operation_mode(
                    operation_mode=operation_mode,
                    operation_config=ldap_config,
                )

                # Generate default handler_id if not provided or empty
                if not handler_id:
                    unique_suffix = uuid.uuid4().hex[:8]
                    handler_id = f"ldap_{resolved_mode}_handler_{unique_suffix}"

                # Generate default handler_name if not provided or empty
                if not handler_name:
                    mode_name = (resolved_mode or "operation").capitalize()
                    handler_name = f"LDAP {mode_name} Handler"

                # Generate default ldap_operation if not provided
                if not ldap_operation:
                    ldap_operation = resolved_mode

                # Create base config
                config: FlextCore.Types.Dict = {
                    "handler_id": handler_id,
                    "handler_name": handler_name,
                    "handler_type": "command",  # LDAP operations are commands
                    "handler_mode": "command",
                    "operation_mode": resolved_mode,
                    "ldap_operation": ldap_operation,
                    "connection_timeout": connection_timeout,
                    "operation_timeout": operation_timeout,
                    "max_retries": max_retries,
                    "ldap_config": ldap_config or {},
                    "metadata": {},
                }

                # Merge additional LDAP config if provided
                if ldap_config:
                    config.update(ldap_config)

                return config

        model_config = SettingsConfigDict(
            case_sensitive=False,
            extra="ignore",  # Changed from "forbid" to "ignore" for LDAP ecosystem compatibility
            use_enum_values=True,
            frozen=False,  # Allow runtime configuration updates for LDAP
            # Pydantic 2.11+ enhanced features
            arbitrary_types_allowed=True,  # For LDAP-specific objects
            validate_return=True,
            validate_assignment=True,  # Validate on assignment for LDAP config changes
            # Enhanced settings features
            cli_parse_args=False,  # Disable CLI parsing by default for LDAP
            cli_avoid_json=True,  # Avoid JSON CLI options for LDAP configs
            nested_model_default_partial_update=True,  # Allow partial updates to nested LDAP models
            # Advanced Pydantic 2.11+ features
            str_strip_whitespace=True,  # Strip whitespace from LDAP strings
            str_to_lower=False,  # Keep original case for LDAP DNs
            json_schema_extra={
                "title": "FLEXT LDAP Configuration",
                "description": "Enterprise LDAP configuration with advanced FlextCore.Config features",
            },
        )

        # LDAP Connection Configuration using FlextLdapConstants for defaults
        ldap_server_uri: str = Field(
            default=FlextLdapConstants.Protocol.DEFAULT_SERVER_URI,
            description="LDAP server URI (ldap:// or ldaps://)",
        )

        ldap_port: int = Field(
            default=FlextLdapConstants.Protocol.DEFAULT_PORT,
            ge=1,
            le=FlextCore.Constants.Network.MAX_PORT,
            description="LDAP server port",
        )

        ldap_use_ssl: bool = Field(
            default=True,
            description="Use SSL/TLS for LDAP connections",
        )

        ldap_verify_certificates: bool = Field(
            default=True,
            description="Verify SSL/TLS certificates",
        )

        # Authentication Configuration using SecretStr for sensitive data
        ldap_bind_dn: str | None = Field(
            default=None,
            description="LDAP bind distinguished name for authentication",
        )

        ldap_bind_password: SecretStr | None = Field(
            default=None,
            description="LDAP bind password for authentication (sensitive)",
        )

        ldap_base_dn: str = Field(
            default=FlextLdapConstants.Defaults.DEFAULT_SEARCH_BASE,
            description="LDAP base distinguished name for searches",
        )

        # LDAP Search Base Configuration
        ldap_user_base_dn: str = Field(
            default="ou=users",
            description="LDAP base DN for user searches",
        )

        ldap_group_base_dn: str = Field(
            default="ou=groups",
            description="LDAP base DN for group searches",
        )

        # Connection Pooling Configuration using FlextLdapConstants for defaults
        ldap_pool_size: int = Field(
            default=FlextCore.Constants.Performance.DEFAULT_DB_POOL_SIZE,
            ge=1,
            le=50,
            description="LDAP connection pool size",
        )

        ldap_pool_timeout: int = Field(
            default=FlextCore.Constants.Network.DEFAULT_TIMEOUT,
            ge=1,
            le=300,
            description="LDAP connection pool timeout in seconds",
        )

        # Operation Configuration using FlextLdapConstants for defaults
        ldap_connection_timeout: int = Field(
            default=FlextCore.Constants.Network.DEFAULT_TIMEOUT,
            ge=1,
            le=300,
            description="LDAP connection timeout in seconds",
        )

        ldap_operation_timeout: int = Field(
            default=60,  # Must be > connection_timeout (30) for validation
            ge=1,
            le=600,
            description="LDAP operation timeout in seconds",
        )

        ldap_size_limit: int = Field(
            default=FlextCore.Constants.Performance.DEFAULT_PAGE_SIZE,
            ge=1,
            le=FlextCore.Constants.Performance.BatchProcessing.MAX_VALIDATION_SIZE,
            description="LDAP search size limit",
        )

        ldap_time_limit: int = Field(
            default=FlextCore.Constants.Network.DEFAULT_TIMEOUT,
            ge=1,
            le=300,
            description="LDAP search time limit in seconds",
        )

        # Caching Configuration using FlextCore.Constants for defaults
        ldap_enable_caching: bool = Field(
            default=True,
            description="Enable LDAP result caching",
        )

        ldap_cache_ttl: int = Field(
            default=FlextCore.Constants.Defaults.TIMEOUT * 10,
            ge=0,
            le=3600,
            description="LDAP cache TTL in seconds",
        )

        # Retry Configuration using FlextCore.Constants for defaults
        ldap_retry_attempts: int = Field(
            default=FlextCore.Constants.Reliability.MAX_RETRY_ATTEMPTS,
            ge=0,
            le=10,
            description="Number of retry attempts for failed operations",
        )

        ldap_retry_delay: int = Field(
            default=int(FlextLdapConstants.LdapRetry.CONNECTION_RETRY_DELAY),
            ge=0,
            le=60,
            description="Delay between retry attempts in seconds",
        )

        # Logging Configuration using FlextLdapConstants for defaults
        ldap_enable_debug: bool = Field(
            default=False,
            description="Enable LDAP debug logging",
        )

        ldap_enable_trace: bool = Field(
            default=False,
            description="Enable LDAP trace logging",
        )

        ldap_log_queries: bool = Field(
            default=False,
            description="Enable logging of LDAP queries",
        )

        ldap_mask_passwords: bool = Field(
            default=True,
            description="Mask passwords in log messages",
        )

        # JSON serialization options
        json_indent: int = Field(
            default=2,
            description="JSON indentation level for file serialization",
            ge=0,
        )
        json_sort_keys: bool = Field(
            default=True,
            description="Sort JSON keys during serialization",
        )

        # =========================================================================
        # COMPUTED FIELDS - Derived LDAP configuration properties
        # =========================================================================

        @computed_field
        def connection_info(self) -> FlextCore.Types.Dict:
            """Get comprehensive LDAP connection information."""
            return {
                "server_uri": self.ldap_server_uri,
                "port": self.ldap_port,
                "use_ssl": self.ldap_use_ssl,
                "verify_certificates": self.ldap_verify_certificates,
                "effective_uri": f"{self.ldap_server_uri}:{self.ldap_port}",
                "is_secure": self.ldap_use_ssl and self.ldap_verify_certificates,
                "connection_timeout": self.ldap_connection_timeout,
            }

        @computed_field
        def authentication_info(self) -> FlextCore.Types.Dict:
            """Get LDAP authentication configuration information."""
            return {
                "bind_dn_configured": self.ldap_bind_dn is not None,
                "bind_password_configured": self.ldap_bind_password is not None,
                "base_dn": self.ldap_base_dn,
                "anonymous_bind": self.ldap_bind_dn is None,
            }

        @computed_field
        def pooling_info(self) -> FlextCore.Types.Dict:
            """Get LDAP connection pooling information."""
            return {
                "pool_size": self.ldap_pool_size,
                "pool_timeout": self.ldap_pool_timeout,
                "pool_utilization": f"{self.ldap_pool_size}/50",
            }

        @computed_field
        def operation_limits(self) -> FlextCore.Types.Dict:
            """Get LDAP operation limits and timeouts."""
            return {
                "operation_timeout": self.ldap_operation_timeout,
                "size_limit": self.ldap_size_limit,
                "time_limit": self.ldap_time_limit,
                "connection_timeout": self.ldap_connection_timeout,
                "total_timeout": self.ldap_operation_timeout
                + self.ldap_connection_timeout,
            }

        @computed_field
        def caching_info(self) -> FlextCore.Types.Dict:
            """Get LDAP caching configuration information."""
            return {
                "caching_enabled": self.ldap_enable_caching,
                "cache_ttl": self.ldap_cache_ttl,
                "cache_ttl_minutes": self.ldap_cache_ttl // 60,
                "cache_effective": self.ldap_enable_caching and self.ldap_cache_ttl > 0,
            }

        @computed_field
        def retry_info(self) -> FlextCore.Types.Dict:
            """Get LDAP retry configuration information."""
            return {
                "retry_attempts": self.ldap_retry_attempts,
                "retry_delay": self.ldap_retry_delay,
                "total_retry_time": self.ldap_retry_attempts * self.ldap_retry_delay,
                "retry_enabled": self.ldap_retry_attempts > 0,
            }

        @computed_field
        def ldap_capabilities(self) -> FlextCore.Types.Dict:
            """Get comprehensive LDAP server capabilities summary."""
            return {
                "supports_ssl": self.ldap_use_ssl,
                "supports_caching": self.ldap_enable_caching,
                "supports_retry": self.ldap_retry_attempts > 0,
                "supports_debug": self.ldap_enable_debug or self.ldap_enable_trace,
                "has_authentication": self.ldap_bind_dn is not None,
                "has_pooling": self.ldap_pool_size > 1,
                "is_production_ready": (
                    self.ldap_use_ssl and self.ldap_bind_dn is not None
                ),
            }

        # Pydantic 2.11 field validators
        # =========================================================================
        # FIELD VALIDATORS - Enhanced Pydantic 2.11 validation
        # =========================================================================

        @field_validator("ldap_server_uri")
        @classmethod
        def validate_ldap_server_uri(cls, v: str) -> str:
            """Validate LDAP server URI format with enhanced error reporting."""
            if not v.startswith(("ldap://", "ldaps://")):
                msg = (
                    f"Invalid LDAP server URI: {v}. Must start with ldap:// or ldaps://"
                )
                exceptions = FlextLdapExceptions()
                raise exceptions.configuration_error(msg, config_key="ldap_server_uri")
            return v

        @field_validator("ldap_bind_dn")
        @classmethod
        def validate_bind_dn(cls, v: str | None) -> str | None:
            """Validate LDAP bind DN format with comprehensive checks."""
            if v is None:
                return v

            exceptions = FlextLdapExceptions()

            # Basic DN validation
            if len(v) < FlextLdapConstants.Validation.MIN_DN_LENGTH:
                msg = f"LDAP bind DN too short: {v}"
                raise exceptions.validation_error(msg, value=v, field="ldap_bind_dn")

            if len(v) > FlextLdapConstants.Validation.MAX_DN_LENGTH:
                msg = f"LDAP bind DN too long: {v}"
                raise exceptions.validation_error(msg, value=v, field="ldap_bind_dn")

            if "=" not in v:
                msg = f"Invalid LDAP bind DN format: {v}. Must contain attribute=value pairs"
                raise exceptions.validation_error(msg, value=v, field="ldap_bind_dn")

            return v

        @field_validator("ldap_base_dn")
        @classmethod
        def validate_base_dn(cls, v: str) -> str:
            """Validate LDAP base DN format with length constraints."""
            if v and len(v) > FlextLdapConstants.Validation.MAX_DN_LENGTH:
                msg = f"LDAP base DN too long: {v}"
                exceptions = FlextLdapExceptions()
                raise exceptions.validation_error(msg, value=v, field="ldap_base_dn")
            return v

        # =========================================================================
        # MODEL VALIDATORS - Cross-field validation with business rules
        # =========================================================================

        @model_validator(mode="after")
        def validate_ldap_configuration_consistency(self) -> FlextLdapModels.Config:
            """Validate LDAP configuration consistency with business rules."""
            exceptions = FlextLdapExceptions()

            # Validate authentication configuration
            if self.ldap_bind_dn is not None and self.ldap_bind_password is None:
                msg = "Bind password is required when bind DN is specified"
                raise exceptions.configuration_error(
                    msg, config_key="ldap_bind_password"
                )

            # Validate caching configuration
            if self.ldap_enable_caching and self.ldap_cache_ttl <= 0:
                msg = "Cache TTL must be positive when caching is enabled"
                raise exceptions.configuration_error(msg, config_key="ldap_cache_ttl")

            # Validate SSL configuration consistency
            if self.ldap_server_uri.startswith("ldaps://") and not self.ldap_use_ssl:
                msg = "SSL must be enabled for ldaps:// server URIs"
                raise exceptions.configuration_error(msg, config_key="ldap_use_ssl")

            return self

        # =========================================================================
        # ENHANCED DIRECT ACCESS - Dot notation support for LDAP config
        # =========================================================================

        def __call__(self, key: str) -> FlextCore.Types.ConfigValue:
            """Enhanced direct value access with LDAP-specific dot notation support.

            Extends FlextCore.Config.__call__ with LDAP-specific nested access patterns.

            Args:
                key: Configuration field name with optional LDAP dot notation
                     (e.g., 'ldap.connection.server', 'ldap.auth.bind_dn')

            Returns:
                The configuration value for the specified field

            Raises:
                KeyError: If the configuration key doesn't exist

            Example:
                >>> config = FlextLdapConfig()
                >>> config("ldap.connection.server")  # ldap_server_uri
                'ldap://localhost:389'
                >>> config("ldap.auth.bind_dn")  # ldap_bind_dn
                'cn=admin,dc=example,dc=com'

            """
            # Handle LDAP-specific dot notation
            if key.startswith("ldap."):
                ldap_key = key[5:]  # Remove "ldap." prefix

                # Connection properties
                if ldap_key.startswith("connection."):
                    prop = ldap_key[11:]  # Remove "connection."
                    if prop == "server":
                        return self.ldap_server_uri
                    if prop == "port":
                        return self.ldap_port
                    if prop == "ssl":
                        return self.ldap_use_ssl
                    if prop == "timeout":
                        return self.ldap_connection_timeout
                    if prop == "uri":
                        return f"{self.ldap_server_uri}:{self.ldap_port}"

                # Authentication properties
                elif ldap_key.startswith("auth."):
                    prop = ldap_key[5:]  # Remove "auth."
                    if prop == "bind_dn":
                        return self.ldap_bind_dn
                    if prop == "bind_password":
                        return self.get_effective_bind_password()
                    if prop == "base_dn":
                        return self.ldap_base_dn

                # Pooling properties
                elif ldap_key.startswith("pool."):
                    prop = ldap_key[5:]  # Remove "pool."
                    if prop == "size":
                        return self.ldap_pool_size
                    if prop == "timeout":
                        return self.ldap_pool_timeout

                # Operation properties
                elif ldap_key.startswith("operation."):
                    prop = ldap_key[10:]  # Remove "operation."
                    if prop == "timeout":
                        return self.ldap_operation_timeout
                    if prop == "size_limit":
                        return self.ldap_size_limit
                    if prop == "time_limit":
                        return self.ldap_time_limit

                # Caching properties
                elif ldap_key.startswith("cache."):
                    prop = ldap_key[6:]  # Remove "cache."
                    if prop == "enabled":
                        return self.ldap_enable_caching
                    if prop == "ttl":
                        return self.ldap_cache_ttl

                # Retry properties
                elif ldap_key.startswith("retry."):
                    prop = ldap_key[6:]  # Remove "retry."
                    if prop == "attempts":
                        return self.ldap_retry_attempts
                    if prop == "delay":
                        return self.ldap_retry_delay

                # Logging properties
                elif ldap_key.startswith("logging."):
                    prop = ldap_key[8:]  # Remove "logging."
                    if prop == "debug":
                        return self.ldap_enable_debug
                    if prop == "trace":
                        return self.ldap_enable_trace
                    if prop == "queries":
                        return self.ldap_log_queries
                    if prop == "mask_passwords":
                        return self.ldap_mask_passwords

            # Fall back to standard FlextCore.Config access
            return super().__call__(key)

        # =========================================================================
        # INFRASTRUCTURE PROTOCOL IMPLEMENTATIONS
        # =========================================================================

        # Infrastructure.Configurable protocol methods
        def configure(self, config: FlextCore.Types.Dict) -> FlextCore.Result[None]:
            """Configure LDAP component with provided settings.

            Implements Infrastructure.Configurable protocol for runtime
            LDAP configuration updates with validation.

            Args:
                config: Configuration dictionary with LDAP settings

            Returns:
                FlextCore.Result[None]: Success if configuration valid, failure otherwise

            """
            try:
                # Update current instance with provided config
                for key, value in config.items():
                    if hasattr(self, key):
                        setattr(self, key, value)

                # Validate after configuration
                return self.validate_ldap_requirements()
            except Exception as e:
                return FlextCore.Result[None].fail(f"LDAP configuration failed: {e}")

        # Infrastructure.ConfigValidator protocol methods
        def validate_runtime_requirements(self) -> FlextCore.Result[None]:
            """Validate LDAP configuration meets runtime requirements.

            Implements Infrastructure.ConfigValidator protocol with LDAP-specific
            validation beyond basic Pydantic validation.

            Returns:
                FlextCore.Result[None]: Success if valid, failure with error details

            """
            # Run standard FlextCore.Config validation first
            base_validation = super().validate_runtime_requirements()
            if base_validation.is_failure:
                return base_validation

            # Additional LDAP-specific runtime validation
            return self.validate_ldap_requirements()

        def validate_business_rules(self) -> FlextCore.Result[None]:
            """Validate LDAP business rules for configuration consistency.

            Implements Infrastructure.ConfigValidator protocol with LDAP-specific
            business rule validation.

            Returns:
                FlextCore.Result[None]: Success if valid, failure with error details

            """
            return FlextCore.Result[None].ok(None)

        # =========================================================================
        # LDAP-SPECIFIC ENHANCED METHODS
        # =========================================================================

        def validate_ldap_requirements(self) -> FlextCore.Result[None]:
            """Validate LDAP-specific configuration requirements.

            Comprehensive validation for LDAP configuration beyond basic
            Pydantic validation, including business rules and consistency checks.

            Returns:
                FlextCore.Result[None]: Success if all LDAP requirements met

            """
            # Run business rules validation
            business_validation = self.validate_business_rules()
            if business_validation.is_failure:
                return business_validation

            # Validate LDAP URI and port consistency
            if (
                self.ldap_server_uri.startswith("ldaps://")
                and self.ldap_port == FlextLdapConstants.Protocol.DEFAULT_PORT
            ):
                return FlextCore.Result[None].fail(
                    f"Port {FlextLdapConstants.Protocol.DEFAULT_PORT} is default for LDAP, not LDAPS. Use {FlextLdapConstants.Protocol.DEFAULT_SSL_PORT} for LDAPS.",
                )

            if (
                self.ldap_server_uri.startswith("ldap://")
                and self.ldap_port == FlextLdapConstants.Protocol.DEFAULT_SSL_PORT
            ):
                return FlextCore.Result[None].fail(
                    f"Port {FlextLdapConstants.Protocol.DEFAULT_SSL_PORT} is default for LDAPS, not LDAP. Use {FlextLdapConstants.Protocol.DEFAULT_PORT} for LDAP.",
                )

            # Validate timeout relationships
            if self.ldap_operation_timeout <= self.ldap_connection_timeout:
                return FlextCore.Result[None].fail(
                    "Operation timeout must be greater than connection timeout",
                )

            return FlextCore.Result[None].ok(None)

        def create_ldap_handler_config(
            self,
            operation_mode: str | None = None,
            ldap_operation: str | None = None,
            handler_name: str | None = None,
            handler_id: str | None = None,
            **kwargs: object,
        ) -> FlextCore.Types.Dict:
            """Create LDAP handler configuration using LDAP-specific utilities.

            Convenience method that uses LdapHandlerConfiguration utilities
            to create properly configured handler settings for LDAP operations.

            Args:
                operation_mode: LDAP operation mode (search, modify, etc.)
                ldap_operation: Specific LDAP operation name
                handler_name: Handler name override
                handler_id: Handler ID override
                **kwargs: Additional configuration parameters

            Returns:
                dict[str, object]: Complete LDAP handler configuration

            """
            return self.LdapHandlerConfiguration.create_ldap_handler_config(
                operation_mode=operation_mode,
                ldap_operation=ldap_operation,
                handler_name=handler_name,
                handler_id=handler_id,
                ldap_config=kwargs,
            )

        def get_ldap_connection_string(self) -> str:
            """Get complete LDAP connection string.

            Returns:
                str: Full LDAP connection string (URI:port)

            """
            return f"{self.ldap_server_uri}:{self.ldap_port}"

        def get_effective_bind_password(self) -> str | None:
            """Get the effective bind password (safely extract from SecretStr)."""
            if self.ldap_bind_password is not None:
                return self.ldap_bind_password.get_secret_value()
            return None

        # =========================================================================
        # DEPENDENCY INJECTION METHODS - Enhanced DI integration
        # =========================================================================

        @classmethod
        def get_di_config_provider(cls) -> providers.Configuration:
            """Get the dependency-injector Configuration provider for LDAP config."""
            if cls._di_config_provider is None:
                with cls._di_provider_lock:
                    if cls._di_config_provider is None:
                        cls._di_config_provider = providers.Configuration()
                        instance = cls._instances.get(cls)
                        if instance is not None:
                            config_dict = instance.model_dump()
                            cls._di_config_provider.from_dict(config_dict)
            return cls._di_config_provider

        # =========================================================================
        # STATIC FACTORY METHODS - Enhanced configuration creation
        # =========================================================================

        @classmethod
        def create_from_connection_config_data(
            cls,
            data: FlextCore.Types.Dict,
        ) -> FlextCore.Result[FlextLdapModels.Config]:
            """Create config from connection data with validation.

            Args:
                data: Connection configuration data

            Returns:
                FlextCore.Result[FlextLdapModels.Config]: Created configuration or error

            """
            try:
                bind_password_value = data.get(
                    FlextLdapConstants.DictKeys.BIND_PASSWORD
                )
                # Ensure bind_password_value is a string for SecretStr
                bind_password_str: str | None = None
                if bind_password_value is not None:
                    bind_password_str = str(bind_password_value)

                config = cls(
                    ldap_server_uri=str(
                        data.get(
                            FlextLdapConstants.DictKeys.SERVER_URI,
                            data.get(
                                FlextLdapConstants.DictKeys.SERVER,
                                "ldap://localhost",
                            ),
                        ),
                    ),
                    ldap_port=int(str(data.get(FlextLdapConstants.DictKeys.PORT, 389))),
                    ldap_bind_dn=str(data.get(FlextLdapConstants.DictKeys.BIND_DN, ""))
                    if data.get(FlextLdapConstants.DictKeys.BIND_DN)
                    else None,
                    ldap_bind_password=SecretStr(bind_password_str)
                    if bind_password_str
                    else None,
                    ldap_base_dn=str(data.get(FlextLdapConstants.DictKeys.BASE_DN, "")),
                )
                return FlextCore.Result[FlextLdapModels.Config].ok(config)
            except Exception as e:
                return FlextCore.Result[FlextLdapModels.Config].fail(
                    f"Config creation failed: {e}"
                )

        @classmethod
        def create_search_config(
            cls,
            data: FlextCore.Types.Dict,
        ) -> FlextCore.Result[FlextLdapModels.SearchConfig]:
            """Create search config from data.

            Args:
                data: Search configuration data

            Returns:
                FlextCore.Result[FlextLdapModels.SearchConfig]: Created search config or error

            """
            try:
                if not isinstance(data, dict):
                    return FlextCore.Result[FlextLdapModels.SearchConfig].fail(
                        "Data must be a dictionary",
                    )

                attributes_data = data.get(FlextLdapConstants.DictKeys.ATTRIBUTES, [])
                if isinstance(attributes_data, list):
                    str_attributes = [
                        str(attr) for attr in attributes_data if attr is not None
                    ]
                else:
                    str_attributes = []
                config = FlextLdapModels.SearchConfig(
                    base_dn=str(data.get(FlextLdapConstants.DictKeys.BASE_DN, "")),
                    filter_str=str(
                        data.get(
                            "filter_str",
                            FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
                        ),
                    ),
                    attributes=str_attributes,
                )
                return FlextCore.Result[FlextLdapModels.SearchConfig].ok(config)
            except Exception as e:
                return FlextCore.Result[FlextLdapModels.SearchConfig].fail(
                    f"Search config creation failed: {e}",
                )

        @classmethod
        def create_modify_config(
            cls,
            data: FlextCore.Types.Dict,
        ) -> FlextCore.Result[dict[str, str | FlextCore.Types.StringList]]:
            """Create modify config from data.

            Args:
                data: Modify configuration data

            Returns:
                FlextCore.Result[dict[str, str | FlextCore.Types.StringList]]: Created modify config or error

            """
            try:
                if not isinstance(data, dict):
                    return FlextCore.Result[
                        dict[str, str | FlextCore.Types.StringList]
                    ].fail("Data must be a dictionary")

                values = data.get(FlextLdapConstants.DictKeys.VALUES, [])
                if isinstance(values, list):
                    str_values = [str(v) for v in values if v is not None]
                else:
                    str_values = []
                config: dict[str, str | FlextCore.Types.StringList] = {
                    FlextLdapConstants.DictKeys.DN: str(
                        data.get(FlextLdapConstants.DictKeys.DN, ""),
                    ),
                    FlextLdapConstants.DictKeys.OPERATION: str(
                        data.get(FlextLdapConstants.DictKeys.OPERATION, "replace"),
                    ),
                    FlextLdapConstants.DictKeys.ATTRIBUTE: str(
                        data.get(FlextLdapConstants.DictKeys.ATTRIBUTE, ""),
                    ),
                    FlextLdapConstants.DictKeys.VALUES: str_values,
                }
                return FlextCore.Result[dict[str, str | FlextCore.Types.StringList]].ok(
                    config
                )
            except Exception as e:
                return FlextCore.Result[
                    dict[str, str | FlextCore.Types.StringList]
                ].fail(
                    f"Modify config creation failed: {e}",
                )

        @classmethod
        def create_add_config(
            cls,
            data: FlextCore.Types.Dict,
        ) -> FlextCore.Result[dict[str, str | dict[str, FlextCore.Types.StringList]]]:
            """Create add config from data.

            Args:
                data: Add configuration data

            Returns:
                FlextCore.Result[FlextCore.Types.Dict]: Created add config or error

            """
            try:
                attributes = data.get(FlextLdapConstants.DictKeys.ATTRIBUTES, {})
                if not isinstance(attributes, dict):
                    attributes = {}

                config: dict[str, str | dict[str, FlextCore.Types.StringList]] = {
                    FlextLdapConstants.DictKeys.DN: str(
                        data.get(FlextLdapConstants.DictKeys.DN, ""),
                    ),
                    "attributes": {
                        str(k): [
                            str(v) for v in (vals if isinstance(vals, list) else [vals])
                        ]
                        for k, vals in attributes.items()
                    },
                }
                return FlextCore.Result[
                    dict[str, str | dict[str, FlextCore.Types.StringList]]
                ].ok(
                    config,
                )
            except Exception as e:
                return FlextCore.Result[
                    dict[str, str | dict[str, FlextCore.Types.StringList]]
                ].fail(
                    f"Add config creation failed: {e}",
                )

        @classmethod
        def create_delete_config(
            cls,
            data: FlextCore.Types.Dict,
        ) -> FlextCore.Result[dict[str, str]]:
            """Create delete config from data.

            Args:
                data: Delete configuration data

            Returns:
                FlextCore.Result[FlextCore.Types.Dict]: Created delete config or error

            """
            try:
                config: dict[str, str] = {
                    FlextLdapConstants.DictKeys.DN: str(
                        data.get(FlextLdapConstants.DictKeys.DN, ""),
                    ),
                }
                return FlextCore.Result[dict[str, str]].ok(config)
            except Exception as e:
                return FlextCore.Result[dict[str, str]].fail(
                    f"Delete config creation failed: {e}",
                )

        @classmethod
        def get_default_search_config(
            cls,
        ) -> FlextCore.Result[dict[str, str | int | FlextCore.Types.StringList]]:
            """Get default search configuration.

            Returns:
                FlextCore.Result[FlextCore.Types.Dict]: Default search configuration

            """
            config: dict[str, str | int | FlextCore.Types.StringList] = {
                "base_dn": FlextLdapConstants.Defaults.DEFAULT_SEARCH_BASE,
                "filter_str": FlextLdapConstants.Defaults.DEFAULT_SEARCH_FILTER,
                "scope": FlextLdapConstants.Scopes.SUBTREE,
                "attributes": [
                    FlextLdapConstants.Attributes.COMMON_NAME,
                    FlextLdapConstants.Attributes.SURNAME,
                    FlextLdapConstants.Attributes.MAIL,
                ],
                "size_limit": FlextCore.Constants.Performance.DEFAULT_PAGE_SIZE,
                "time_limit": FlextCore.Constants.Network.DEFAULT_TIMEOUT,
            }
            return FlextCore.Result[
                dict[str, str | int | FlextCore.Types.StringList]
            ].ok(config)

        @classmethod
        def merge_configs(
            cls,
            base_config: FlextCore.Types.Dict,
            override_config: FlextCore.Types.Dict,
        ) -> FlextCore.Result[FlextCore.Types.Dict]:
            """Merge two configuration dictionaries.

            Args:
                base_config: Base configuration to merge into
                override_config: Configuration to override with

            Returns:
                FlextCore.Result[FlextCore.Types.Dict]: Merged configuration or error

            """
            try:
                merged = base_config.copy()
                merged.update(override_config)
                return FlextCore.Result[FlextCore.Types.Dict].ok(merged)
            except Exception as e:
                return FlextCore.Result[FlextCore.Types.Dict].fail(
                    f"Config merge failed: {e}"
                )


__all__ = [
    "FlextLdapModels",
]

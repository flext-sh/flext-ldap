"""Unified LDAP models for flext-ldap - ALL models consolidated into FlextLdapModels.

This module consolidates ALL LDAP models, entities, and value objects into a single
FlextLdapModels class following FLEXT one-class-per-module standards.

Eliminates previous triple model system (models.py + entities.py + value_objects.py).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

TYPE CHECKER KNOWN ISSUES (Isolated until flext-core patterns stabilize):
===========================================================================

1. DistinguishedName.create() return type (Lines 243, 255, 257, 261):
   - Pyrefly reports: FlextResult[DistinguishedName] not assignable to FlextResult[object]
   - Reason: Generic type inference limitation with nested FlextModels classes
   - Impact: None - runtime behavior is correct, type is properly constrained
   - Resolution: Waiting for flext-core TypeVar propagation improvements

2. LdapUser.created_at override (Line 609):
   - Pyrefly reports: datetime | None overrides Entity.created_at inconsistently
   - Reason: Domain model requires Optional timestamp, Entity base class requires non-null
   - Impact: None - Pydantic validation handles None values correctly
   - Resolution: Architectural decision - LDAP users may not have creation timestamps

3. Entry.additional_attributes access (Line 951):
   - Pyrefly reports: object | None not assignable to list[str] | str | None
   - Reason: Dict.get() returns object | None, but LDAP attributes are strongly typed
   - Impact: None - LDAP protocol guarantees attribute values are str or list[str]
   - Resolution: Runtime type narrowing via LDAP protocol constraints

4. Config.validate() method override (Lines 2406, 2430, 2453, 2475):
   - Pyrefly reports: Instance method incompatible with classmethod signature
   - Reason: Changed from Pydantic @model_validator to explicit validate() pattern
   - Impact: None - Explicit validation allows object creation without auto-validation
   - Resolution: Pattern change for FlextResult compatibility (see validation tests)

All other type errors have been fixed. These remaining issues are architectural decisions
or generic type limitations that do not affect runtime correctness.
"""

from __future__ import annotations

import base64
from datetime import datetime
from enum import Enum
from typing import ClassVar, override

from flext_core import (
    FlextConstants,
    FlextModels,
    FlextResult,
    FlextTypes,
    FlextUtilities,
)
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

from flext_ldap.constants import FlextLdapConstants
from flext_ldap.exceptions import FlextLdapExceptions
from flext_ldap.typings import FlextLdapTypes
from flext_ldap.validations import FlextLdapValidations


class FlextLdapModels(FlextModels):
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
        use_enum_values=True,
        arbitrary_types_allowed=True,
        validate_return=True,
        ser_json_timedelta="iso8601",
        ser_json_bytes="base64",
        serialize_by_alias=True,
        populate_by_name=True,
        str_strip_whitespace=True,
        validate_default=True,
        # LDAP-specific configurations
        frozen=False,  # Allow mutable LDAP models for attribute updates
        extra="forbid",  # Strict LDAP attribute validation
        # LDAP serialization features
        json_encoders={
            datetime: lambda v: v.isoformat() if v else None,
        },
    )

    # =========================================================================
    # VALUE OBJECTS - Immutable LDAP value objects
    # =========================================================================

    class DistinguishedName(FlextModels.Value):
        """LDAP Distinguished Name value object with RFC 2253 compliance.

        Extends FlextModels.Value for proper Pydantic 2 validation and composition.
        Enhanced with advanced Pydantic 2.11 features for LDAP-specific validation.
        """

        model_config = ConfigDict(
            validate_assignment=True,
            str_strip_whitespace=True,
            frozen=True,  # DN is immutable value object
            extra="forbid",
            # LDAP-specific serialization
        )

        value: str = Field(
            ...,
            min_length=1,
            description="Distinguished Name string",
            pattern=r"^[a-zA-Z]+=.+",  # Basic DN pattern
            examples=[
                "cn=John Doe,ou=users,dc=example,dc=com",
                "uid=REDACTED_LDAP_BIND_PASSWORD,dc=ldap,dc=local",
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
            components: FlextTypes.StringList = []
            for comp in value.split(","):
                component = comp.strip()
                if "=" in component:
                    attr, val = component.split("=", 1)
                    # Normalize attribute name to lowercase, preserve value case
                    normalized_component = f"{attr.strip().lower()}={val.strip()}"
                    components.append(normalized_component)
            return ",".join(components)

        @classmethod
        @override
        def create(cls, *args: object, **kwargs: object) -> FlextResult[object]:
            """Create DN with validation - compatible with base class signature."""
            try:
                # Handle single argument case for DN string
                if len(args) == 1 and not kwargs:
                    dn_string = str(args[0])
                    dn_obj = cls(value=dn_string.strip())
                    return FlextResult[object].ok(dn_obj)

                # Handle kwargs case - ensure value is string
                if "value" in kwargs:
                    kwargs["value"] = str(kwargs["value"])

                # Convert all kwargs to proper types for Pydantic validation
                typed_kwargs: FlextTypes.StringDict = {}
                for k, v in kwargs.items():
                    typed_kwargs[k] = str(v)

                dn_obj = cls(**typed_kwargs)
                return FlextResult[object].ok(dn_obj)
            except FlextLdapExceptions.LdapValidationError as e:
                return FlextResult[object].fail(
                    f"DN creation failed: {e}",
                )
            except Exception as e:
                return FlextResult[object].fail(
                    f"DN creation failed: {e}",
                )

    class Filter(FlextModels.Value):
        """LDAP filter value object with RFC 4515 compliance.

        Extends FlextModels.Value for proper Pydantic 2 validation and composition.
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

    class Scope(FlextModels.Value):
        """LDAP search scope value object.

        Extends FlextModels.Value for proper Pydantic 2 validation and composition.
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

    class SchemaAttribute(FlextModels.Value):
        """LDAP schema attribute definition.

        Extends FlextModels.Value for proper Pydantic 2 validation and composition.
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

    class SchemaObjectClass(FlextModels.Value):
        """LDAP schema object class definition.

        Extends FlextModels.Value for proper Pydantic 2 validation and composition.
        """

        name: str = Field(..., description="Object class name")
        oid: str = Field(..., description="Object identifier")
        superior: FlextTypes.StringList = Field(
            default_factory=list,
            description="Superior classes",
        )
        must: FlextTypes.StringList = Field(
            default_factory=list,
            description="Required attributes",
        )
        may: FlextTypes.StringList = Field(
            default_factory=list,
            description="Optional attributes",
        )
        kind: str = Field(default="STRUCTURAL", description="Object class kind")
        is_obsolete: bool = Field(default=False, description="Obsolete flag")

    class ServerQuirks(FlextModels.Value):
        """LDAP server-specific quirks and behaviors - Pydantic Value Object."""

        model_config = ConfigDict(frozen=True)

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
        attribute_name_mappings: FlextTypes.StringDict = Field(default_factory=dict)
        object_class_mappings: FlextTypes.StringDict = Field(default_factory=dict)
        dn_format_preferences: FlextTypes.StringList = Field(default_factory=list)
        search_scope_limitations: set[str] = Field(default_factory=set)
        filter_syntax_quirks: FlextTypes.StringList = Field(default_factory=list)
        modify_operation_quirks: FlextTypes.StringList = Field(default_factory=list)

    class SchemaDiscoveryResult(FlextModels.Entity):
        """Result of LDAP schema discovery operation - Pydantic Entity."""

        # Note: Cannot use frozen=True with Entity (has default timestamp fields)

        server_info: FlextTypes.Dict
        server_type: FlextLdapModels.LdapServerType
        server_quirks: FlextLdapModels.ServerQuirks
        attributes: dict[str, FlextLdapModels.SchemaAttribute]
        object_classes: dict[str, FlextLdapModels.SchemaObjectClass]
        naming_contexts: FlextTypes.StringList
        supported_controls: FlextTypes.StringList
        supported_extensions: FlextTypes.StringList

    # =========================================================================
    # BASE CLASSES - Common functionality for LDAP entities
    # =========================================================================

    class Base(FlextModels.ArbitraryTypesModel):
        """Base model class with dynamic LDAP entity support.

        **DYNAMIC LDAP SCHEMA**: Allows arbitrary attributes to support varying LDAP server schemas
        (OpenLDAP, Active Directory, Oracle OID/OUD, 389 DS, etc.) with different custom attributes.

        Uses ArbitraryTypesModel with extra="allow" to accept any LDAP attribute from any server type.
        """

        model_config = ConfigDict(
            extra="allow",  # CRITICAL: Allow arbitrary LDAP attributes from any server schema
            arbitrary_types_allowed=True,
            validate_assignment=True,
            str_strip_whitespace=True,
        )

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
            validation_result: FlextResult[None] = FlextLdapValidations.validate_dn(
                v,
            ).map(lambda _: None)
            if validation_result.is_failure:
                exceptions = FlextLdapExceptions()
                error_msg = validation_result.error or "DN validation failed"
                raise exceptions.validation_error(error_msg, value=v, field="dn")
            return v.strip()

        @staticmethod
        def validate_email_field(value: str | None) -> str | None:
            """Common email validation using flext-core FlextUtilities."""
            if value is None:
                return None

            # Use flext-core validation directly (returns FlextResult[str])
            validation_result = FlextUtilities.Validation.validate_email(value)
            if validation_result.is_failure:
                exceptions = FlextLdapExceptions()
                error_msg = validation_result.error or "Email validation failed"
                raise exceptions.validation_error(error_msg, value=value, field="email")
            return value

        @staticmethod
        def validate_password_field(value: str | None) -> str | None:
            """Common password validation using centralized validation."""
            validation_result: FlextResult[None] = (
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

    class EntityBase(Base, ValidationMixin):
        """Base class for LDAP entities with common fields and validation.

        Provides common fields and validation methods that are shared
        across multiple LDAP entity types.
        """

        # Timestamp fields inherited from Base

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

    class LdapUser(FlextModels.Entity):
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
        object_classes: FlextTypes.StringList = Field(
            default_factory=lambda: ["person", "organizationalPerson", "inetOrgPerson"],
            description="LDAP object classes",
        )

        # Core enterprise fields
        status: str | None = Field(
            default=FlextLdapConstants.Defaults.DEFAULT_STATUS,
            description="User status",
        )
        additional_attributes: FlextTypes.Dict = Field(
            default_factory=dict,
            description="Additional LDAP attributes",
        )
        # Override TimestampableMixin's non-nullable created_at - architectural decision
        # LDAP users may not have creation timestamps in all directory implementations
        created_at: datetime | None = Field(
            default=None,
            description="Creation timestamp",
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

        @classmethod
        def validate_dn_field(cls, v: str) -> str:
            """Validate DN field using centralized validation."""
            if not v or not v.strip():
                msg = "DN cannot be empty"
                raise ValueError(msg)
            return v

        @classmethod
        def validate_email_field(cls, v: str | None) -> str | None:
            """Validate email field using centralized validation."""
            if v is None:
                return None
            if not v or "@" not in v:
                msg = "Invalid email format"
                raise ValueError(msg)
            return v

        @classmethod
        def validate_required_string_field(cls, v: str) -> str:
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
            v: FlextTypes.StringList,
        ) -> FlextTypes.StringList:
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

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate user business rules with enhanced error handling."""
            # Explicit FlextResult error handling - NO try/except

            # User-specific validations
            if "person" not in self.object_classes:
                return FlextResult[None].fail("User must have 'person' object class")

            if not self.cn:
                return FlextResult[None].fail("User must have a Common Name")

            return FlextResult[None].ok(None)

        def to_ldap_attributes(self) -> dict[str, FlextTypes.StringList]:
            """Convert user to LDAP attributes format."""
            attributes: dict[str, FlextTypes.StringList] = {}

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
            for key, value in self.additional_attributes.items():
                if isinstance(value, list):
                    attributes[key] = [str(v) for v in value]
                else:
                    attributes[key] = [str(value)]

            return attributes

        @classmethod
        def from_ldap_attributes(
            cls,
            ldap_attributes: dict[str, FlextTypes.StringList],
        ) -> FlextResult[FlextLdapModels.LdapUser]:
            """Create user from LDAP attributes."""
            # Explicit FlextResult error handling - NO try/except

            # Extract DN
            dn_values = ldap_attributes.get(
                FlextLdapConstants.LdapAttributeNames.DN,
                [],
            )
            if not dn_values:
                return FlextResult[FlextLdapModels.LdapUser].fail("DN is required")
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
                created_at=None,
                display_name=cn,
                modified_at=None,
                created_timestamp=None,
                modified_timestamp=None,
            )

            return FlextResult[FlextLdapModels.LdapUser].ok(user)

        def get_attribute(
            self,
            name: str,
        ) -> FlextLdapTypes.LdapEntries.EntryAttributeValue | None:
            """Get attribute value by name with enhanced error handling."""
            # Explicit FlextResult error handling - NO try/except
            from typing import cast

            # LDAP protocol guarantees attribute values are str or list[str]
            return cast(
                "FlextLdapTypes.LdapEntries.EntryAttributeValue | None",
                self.additional_attributes.get(name),
            )

        def set_attribute(
            self,
            name: str,
            value: FlextLdapTypes.LdapEntries.EntryAttributeValue,
        ) -> None:
            """Set attribute value by name with enhanced error handling."""
            # Explicit FlextResult error handling - NO try/except
            self.additional_attributes[name] = value

        def get_rdn(self) -> str:
            """Extract Relative Distinguished Name (first component) with enhanced error handling."""
            # Explicit FlextResult error handling - NO try/except
            return self.dn.split(",")[0] if "," in self.dn else self.dn

        def get_parent_dn(self) -> str | None:
            """Extract parent DN with enhanced error handling."""
            # Explicit FlextResult error handling - NO try/except
            parts = self.dn.split(",", 1)
            return parts[1] if len(parts) > 1 else None

        @classmethod
        def create_minimal(
            cls,
            dn: str,
            cn: str,
            uid: str | None = None,
            **kwargs: object,
        ) -> FlextResult[FlextLdapModels.LdapUser]:
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
                return FlextResult[FlextLdapModels.LdapUser].ok(user)
            except FlextLdapExceptions.LdapValidationError as e:
                return FlextResult[FlextLdapModels.LdapUser].fail(
                    f"User creation failed: {e}",
                )
            except Exception as e:
                return FlextResult[FlextLdapModels.LdapUser].fail(
                    f"User creation failed: {e}",
                )

    class Group(FlextModels.Entity):
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
        member_dns: FlextTypes.StringList = Field(
            default_factory=list,
            description="Member Distinguished Names",
        )
        unique_member_dns: FlextTypes.StringList = Field(
            default_factory=list,
            description="Unique Member Distinguished Names",
        )

        # Core enterprise fields
        status: str | None = Field(default=None, description="Group status")
        additional_attributes: FlextTypes.Dict = Field(
            default_factory=dict,
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
        object_classes: FlextTypes.StringList = Field(
            default_factory=lambda: ["groupOfNames", "top"],
            description="LDAP object classes",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format using centralized validation."""
            return FlextLdapModels.ValidationMixin.validate_dn_field(v)

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate group business rules with enhanced error handling."""
            # Explicit FlextResult error handling - NO try/except

            # Group-specific validations
            if "groupOfNames" not in self.object_classes:
                return FlextResult[None].fail(
                    "Group must have 'groupOfNames' object class",
                )

            return FlextResult[None].ok(None)

        def to_ldap_attributes(self) -> dict[str, FlextTypes.StringList]:
            """Convert group to LDAP attributes format."""
            attributes: dict[str, FlextTypes.StringList] = {}

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
            for key, value in self.additional_attributes.items():
                if isinstance(value, list):
                    attributes[key] = [str(v) for v in value]
                else:
                    attributes[key] = [str(value)]

            return attributes

        @classmethod
        def from_ldap_attributes(
            cls,
            ldap_attributes: dict[str, FlextTypes.StringList],
        ) -> FlextResult[FlextLdapModels.Group]:
            """Create group from LDAP attributes."""
            # Explicit FlextResult error handling - NO try/except

            # Extract DN
            dn_values = ldap_attributes.get(
                FlextLdapConstants.LdapAttributeNames.DN,
                [],
            )
            if not dn_values:
                return FlextResult[FlextLdapModels.Group].fail("DN is required")
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
                additional_attributes={},
                created_timestamp=None,
                modified_timestamp=None,
            )

            return FlextResult[FlextLdapModels.Group].ok(group)

        def has_member(self, member_dn: str) -> bool:
            """Check if DN is a member of this group with enhanced error handling."""
            # Explicit FlextResult error handling - NO try/except
            return member_dn in self.member_dns or member_dn in self.unique_member_dns

        def add_member(self, member_dn: str) -> FlextResult[None]:
            """Add member to group with enhanced error handling."""
            # Explicit FlextResult error handling - NO try/except
            if member_dn not in self.member_dns:
                self.member_dns.append(member_dn)
            return FlextResult[None].ok(None)

        def remove_member(self, member_dn: str) -> FlextResult[None]:
            """Remove member from group with enhanced error handling."""
            # Explicit FlextResult error handling - NO try/except
            if member_dn in self.member_dns:
                self.member_dns.remove(member_dn)
                return FlextResult[None].ok(None)
            return FlextResult[None].fail(f"Member {member_dn} not found in group")

        @classmethod
        def create_minimal(
            cls,
            dn: str,
            cn: str,
            gid_number: int | None = None,
            description: str | None = None,
            **_kwargs: object,
        ) -> FlextResult[FlextLdapModels.Group]:
            """Create minimal group with required fields only and enhanced error handling."""
            # Explicit FlextResult error handling - NO try/except

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
            return FlextResult[FlextLdapModels.Group].ok(group)

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
        object_classes: FlextTypes.StringList = Field(
            default_factory=list,
            description="LDAP object classes",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format using centralized validation."""
            return FlextLdapModels.ValidationMixin.validate_dn_field(v)

        def get_attribute(
            self,
            name: str,
        ) -> FlextLdapTypes.LdapEntries.EntryAttributeValue | None:
            """Get attribute value by name with enhanced error handling.

            Args:
                name: Attribute name.

            Returns:
                Attribute value or None if not found.

            """
            # Explicit FlextResult error handling - NO try/except
            attribute_value = self.attributes.get(name)
            if attribute_value is None:
                return None

            # Convert different types to string list for consistent access
            if isinstance(attribute_value, str):
                return [attribute_value]
            # attribute_value is FlextTypes.StringList at this point due to type narrowing
            if attribute_value:  # Check if list is not empty
                # Convert all items to strings
                return [
                    item.decode("utf-8") if isinstance(item, bytes) else str(item)
                    for item in attribute_value
                ]
            # Empty list case
            return []

        def set_attribute(
            self,
            name: str,
            value: FlextLdapTypes.LdapEntries.EntryAttributeValue,
        ) -> None:
            """Set attribute value by name with enhanced error handling."""
            # Explicit FlextResult error handling - NO try/except
            self.attributes[name] = value

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists with enhanced error handling."""
            # Explicit FlextResult error handling - NO try/except
            return name in self.attributes

        def get_rdn(self) -> str:
            """Extract Relative Distinguished Name with enhanced error handling."""
            # Explicit FlextResult error handling - NO try/except
            return self.dn.split(",")[0] if "," in self.dn else self.dn

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
            return self.get_attribute(key)

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
            return self.get_attribute(key) or default

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

    # =========================================================================
    # LDAP OPERATION ENTITIES - Request/Response Objects
    # =========================================================================

    class SearchRequest(Base, ValidationMixin):
        """LDAP Search Request entity with comprehensive parameters and advanced Pydantic 2.11 features."""

        # Search scope
        base_dn: str = Field(..., description="Search base Distinguished Name")
        filter_str: str = Field(..., description="LDAP search filter")
        scope: str = Field(
            default="subtree",
            description="Search scope: base, onelevel, subtree",
            pattern="^(base|onelevel|subtree|BASE|ONELEVEL|SUBTREE)$",
        )

        # Attribute selection
        attributes: FlextTypes.StringList | None = Field(
            default=None,
            description="Attributes to return (None = all)",
        )

        # Search limits - using centralized constants
        size_limit: int = Field(
            default=FlextConstants.Performance.BatchProcessing.MAX_VALIDATION_SIZE,
            description="Maximum number of entries to return",
            ge=0,
        )
        time_limit: int = Field(
            default=FlextConstants.Network.DEFAULT_TIMEOUT,
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
            validation_result: FlextResult[None] = FlextLdapValidations.validate_filter(
                v,
            ).map(lambda _: None)
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
            v: FlextTypes.StringList | None,
        ) -> FlextTypes.StringList | None:
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
            attributes: FlextTypes.StringList | None = None,
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
            attributes: FlextTypes.StringList | None = None,
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
            scope: str = FlextConstants.Platform.LDAP_SCOPE_SUBTREE,
            attributes: FlextTypes.StringList | None = None,
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
                    page_size=FlextConstants.Performance.DEFAULT_PAGE_SIZE,
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
                "page_size": FlextConstants.Performance.DEFAULT_PAGE_SIZE,
                "paged_cookie": b"",
                "size_limit": FlextConstants.Performance.BatchProcessing.MAX_VALIDATION_SIZE,
                "time_limit": FlextConstants.Network.DEFAULT_TIMEOUT,
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
        def get_user_attributes() -> list[str]:
            """Get default user attributes to retrieve.

            Returns the standard set of LDAP user attributes commonly needed
            for user operations.

            Returns:
                List of default user attribute names

            Example:
                attrs = SearchRequest.get_user_attributes()
                # ["uid", "cn", "sn", "mail", "objectClass"]

            """
            return ["uid", "cn", "sn", "mail", "objectClass"]

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
                filter_str = SearchRequest.create_group_filter("(cn=REDACTED_LDAP_BIND_PASSWORDs)")
                # "(&(objectClass=groupOfNames)(cn=REDACTED_LDAP_BIND_PASSWORDs))"

            """
            base_filter = "(objectClass=groupOfNames)"
            if group_filter:
                return f"(&{base_filter}{group_filter})"
            return base_filter

        @staticmethod
        def get_group_attributes() -> list[str]:
            """Get default group attributes to retrieve.

            Returns the standard set of LDAP group attributes commonly needed
            for group operations.

            Returns:
                List of default group attribute names

            Example:
                attrs = SearchRequest.get_group_attributes()
                # ["cn", "member", "description", "objectClass"]

            """
            return ["cn", "member", "description", "objectClass"]

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
        object_classes: FlextTypes.StringList = Field(
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

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate create user request business rules."""
            if not self.dn:
                return FlextResult[None].fail("DN cannot be empty")
            if not self.uid:
                return FlextResult[None].fail("UID cannot be empty")
            if not self.cn:
                return FlextResult[None].fail("Common Name cannot be empty")
            if not self.mail:
                return FlextResult[None].fail("Email cannot be empty")
            if not self.user_password:
                return FlextResult[None].fail("Password cannot be empty")
            return FlextResult[None].ok(None)

        def to_user_entity(self) -> FlextLdapModels.LdapUser:
            """Convert request to user entity."""
            from typing import cast

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
                # Dict variance: str|list[str] is compatible with object
                additional_attributes=cast(
                    "dict[str, object]",
                    self.additional_attributes,
                ),
                created_at=None,
                modified_at=None,
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
        members: FlextTypes.StringList = Field(..., description="Initial group members")

        # LDAP metadata
        object_classes: FlextTypes.StringList = Field(
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
        def validate_members(cls, v: FlextTypes.StringList) -> FlextTypes.StringList:
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

        Uses FlextModels patterns for centralized validation and parameter management.
        Supports any LDAP object class with flexible attribute handling.
        """

        # Required fields
        dn: str = Field(..., description="Distinguished Name for new entry")
        attributes: dict[str, str | FlextTypes.StringList] = Field(
            ...,
            description="Entry attributes as key-value pairs",
        )

        # Optional object classes - defaults will be determined by attributes if not specified
        object_classes: FlextTypes.StringList | None = Field(
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
            v: dict[str, str | FlextTypes.StringList],
        ) -> dict[str, str | FlextTypes.StringList]:
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

        def _detect_object_classes_from_attributes(self) -> FlextTypes.StringList:
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

        def to_ldap_attributes(self) -> dict[str, FlextTypes.StringList]:
            """Convert attributes to LDAP format (all values as lists)."""
            ldap_attrs = {}
            for key, value in self.attributes.items():
                if isinstance(value, list):
                    ldap_attrs[key] = value
                else:
                    ldap_attrs[key] = [str(value)]
            return ldap_attrs

    # =========================================================================
    # CONNECTION AND CONFIGURATION ENTITIES
    # =========================================================================

    class ConnectionInfo(Base, ValidationMixin):
        """LDAP Connection Information entity."""

        # Connection details
        server: str = Field(default="localhost", description="LDAP server hostname/IP")
        port: int = Field(
            FlextConstants.Platform.LDAP_DEFAULT_PORT,
            description="LDAP server port",
            ge=1,
            le=FlextConstants.Network.MAX_PORT,
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
            FlextConstants.Network.DEFAULT_TIMEOUT,
            description="Connection timeout in seconds",
            ge=1,
        )
        pool_size: int = Field(
            FlextConstants.Performance.DEFAULT_DB_POOL_SIZE,
            description="Connection pool size",
            ge=1,
        )
        pool_keepalive: int = Field(
            FlextConstants.Performance.DEFAULT_TTL_SECONDS,
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
            if v <= 0 or v > FlextConstants.Network.MAX_PORT:
                msg = f"Port must be between 1 and {FlextConstants.Network.MAX_PORT}"
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
        server_info: FlextTypes.Dict = Field(
            default_factory=dict,
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
        data: FlextTypes.Dict = Field(
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
            data: FlextTypes.Dict | None = None,
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

    class ConnectionConfig(FlextModels.Value):
        """LDAP connection configuration value object - Pydantic Value Object."""

        model_config = ConfigDict(frozen=True)

        server: str
        port: int = FlextConstants.Platform.LDAP_DEFAULT_PORT
        use_ssl: bool = False
        bind_dn: str | None = None
        bind_password: str | None = None
        timeout: int = FlextConstants.Network.DEFAULT_TIMEOUT

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

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate the configuration business rules and return FlextResult.

            Returns:
                FlextResult[None] indicating validation success or failure

            """
            try:
                if not self.server or not self.server.strip():
                    return FlextResult[None].fail("Server cannot be empty")
                max_port = 65535
                if self.port <= 0 or self.port > max_port:
                    return FlextResult[None].fail("Invalid port number")
                return FlextResult[None].ok(None)
            except Exception as e:
                return FlextResult[None].fail(f"Validation failed: {e}")

    class ModifyConfig(FlextModels.Command):
        """LDAP modify operation configuration - Pydantic Command."""

        model_config = ConfigDict(frozen=True)

        dn: str
        changes: dict[str, list[tuple[str, FlextTypes.StringList]]]

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate the configuration business rules and return FlextResult.

            Returns:
                FlextResult[None] indicating validation success or failure

            """
            try:
                if not self.dn or not self.dn.strip():
                    return FlextResult[None].fail("DN cannot be empty")
                if not self.changes:
                    return FlextResult[None].fail("Changes cannot be empty")
                return FlextResult[None].ok(None)
            except Exception as e:
                return FlextResult[None].fail(f"Validation failed: {e}")

    class AddConfig(FlextModels.Command):
        """LDAP add operation configuration - Pydantic Command."""

        model_config = ConfigDict(frozen=True)

        dn: str
        attributes: dict[str, FlextTypes.StringList]

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate the configuration business rules and return FlextResult.

            Returns:
                FlextResult[None] indicating validation success or failure

            """
            try:
                if not self.dn or not self.dn.strip():
                    return FlextResult[None].fail("DN cannot be empty")
                if not self.attributes:
                    return FlextResult[None].fail("Attributes cannot be empty")
                return FlextResult[None].ok(None)
            except Exception as e:
                return FlextResult[None].fail(f"Validation failed: {e}")

    class DeleteConfig(FlextModels.Command):
        """LDAP delete operation configuration - Pydantic Command."""

        model_config = ConfigDict(frozen=True)

        dn: str

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate the configuration business rules and return FlextResult.

            Returns:
                FlextResult[None] indicating validation success or failure

            """
            try:
                if not self.dn or not self.dn.strip():
                    return FlextResult[None].fail("DN cannot be empty")
                return FlextResult[None].ok(None)
            except Exception as e:
                return FlextResult[None].fail(f"Validation failed: {e}")

    class SearchConfig(FlextModels.Query):
        """LDAP search operation configuration - Pydantic Query."""

        model_config = ConfigDict(frozen=True)

        base_dn: str
        filter_str: str
        attributes: FlextTypes.StringList

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
        payload: FlextTypes.Dict = Field(
            default_factory=dict,
            description="Command payload data",
        )
        metadata: FlextTypes.Dict = Field(
            default_factory=dict,
            description="Command metadata",
        )
        timestamp: int | None = Field(default=None, description="Command timestamp")

        @classmethod
        def create(
            cls,
            command_type: str,
            command_id: str,
            payload: FlextTypes.Dict | None = None,
            metadata: FlextTypes.Dict | None = None,
            timestamp: int | None = None,
        ) -> FlextResult[FlextLdapModels.CqrsCommand]:
            """Create CQRS command message."""
            # Explicit FlextResult error handling - NO try/except
            instance = cls(
                command_type=command_type,
                command_id=command_id,
                payload=payload or {},
                metadata=metadata or {},
                timestamp=timestamp,
            )
            return FlextResult[FlextLdapModels.CqrsCommand].ok(instance)

    class CqrsQuery(Base):
        """CQRS Query message envelope."""

        query_type: str = Field(default="", description="Query type identifier")
        query_id: str = Field(default="", description="Unique query identifier")
        parameters: FlextTypes.Dict = Field(
            default_factory=dict,
            description="Query parameters",
        )
        metadata: FlextTypes.Dict = Field(
            default_factory=dict,
            description="Query metadata",
        )
        timestamp: int | None = Field(default=None, description="Query timestamp")

        @classmethod
        def create(
            cls,
            query_type: str,
            query_id: str,
            parameters: FlextTypes.Dict | None = None,
            metadata: FlextTypes.Dict | None = None,
            timestamp: int | None = None,
        ) -> FlextResult[FlextLdapModels.CqrsQuery]:
            """Create CQRS query message."""
            # Explicit FlextResult error handling - NO try/except
            instance = cls(
                query_type=query_type,
                query_id=query_id,
                parameters=parameters or {},
                metadata=metadata or {},
                timestamp=timestamp,
            )
            return FlextResult[FlextLdapModels.CqrsQuery].ok(instance)

    class CqrsEvent(Base):
        """CQRS Event message envelope for domain events."""

        event_type: str = Field(default="", description="Event type identifier")
        event_id: str = Field(default="", description="Unique event identifier")
        aggregate_id: str = Field(default="", description="Aggregate root identifier")
        payload: FlextTypes.Dict = Field(
            default_factory=dict,
            description="Event payload data",
        )
        metadata: FlextTypes.Dict = Field(
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
            payload: FlextTypes.Dict | None = None,
            metadata: FlextTypes.Dict | None = None,
            version: int = 1,
        ) -> FlextResult[FlextLdapModels.CqrsEvent]:
            """Create CQRS event message."""
            # Explicit FlextResult error handling - NO try/except
            instance = cls(
                event_type=event_type,
                event_id=event_id,
                aggregate_id=aggregate_id,
                payload=payload or {},
                metadata=metadata or {},
                timestamp=timestamp,
                version=version,
            )
            return FlextResult[FlextLdapModels.CqrsEvent].ok(instance)

    class DomainMessage(Base):
        """Generic domain message envelope for CQRS infrastructure."""

        message_type: str = Field(..., description="Message type identifier")
        message_id: str = Field(..., description="Unique message identifier")
        data: FlextTypes.Dict = Field(default_factory=dict, description="Message data")
        metadata: FlextTypes.Dict = Field(
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
            data: FlextTypes.Dict | None = None,
            metadata: FlextTypes.Dict | None = None,
            timestamp: int | None = None,
            *,
            processed: bool = False,
        ) -> FlextResult[FlextLdapModels.DomainMessage]:
            """Create domain message."""
            # Explicit FlextResult error handling - NO try/except
            instance = cls(
                message_type=message_type,
                message_id=message_id,
                data=data or {},
                metadata=metadata or {},
                timestamp=timestamp,
                processed=processed,
            )
            return FlextResult[FlextLdapModels.DomainMessage].ok(instance)

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
        attributes: FlextTypes.StringList = Field(
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
            attributes: FlextTypes.StringList | None = None,
            filter_expression: str = "",
            scope: str = "subtree",
        ) -> FlextResult[FlextLdapModels.AclTarget]:
            """Create AclTarget instance.

            Factory method for creating AclTarget with FlextResult error handling.

            Args:
                target_type: Target type (entry, attr, etc.)
                dn_pattern: DN pattern for target matching
                attributes: Target attributes (empty means all)
                filter_expression: LDAP filter for target matching
                scope: Search scope for target

            Returns:
                FlextResult[AclTarget] containing the created instance

            """
            # Explicit FlextResult error handling - NO try/except
            return FlextResult.ok(
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
        ) -> FlextResult[FlextLdapModels.AclSubject]:
            """Create AclSubject instance."""
            # Explicit FlextResult error handling - NO try/except
            return FlextResult.ok(
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
        granted_permissions: FlextTypes.StringList = Field(
            default_factory=list,
            description="Granted permissions (read, write, etc.)",
        )
        denied_permissions: FlextTypes.StringList = Field(
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
        def permissions(self) -> FlextTypes.StringList:
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
            permissions: FlextTypes.StringList,
            denied_permissions: FlextTypes.StringList | None = None,
            grant_type: str = "allow",
        ) -> FlextResult[FlextLdapModels.AclPermissions]:
            """Create AclPermissions instance."""
            # Explicit FlextResult error handling - NO try/except
            return FlextResult.ok(
                cls(
                    granted_permissions=permissions,
                    denied_permissions=denied_permissions or [],
                    grant_type=grant_type,
                ),
            )

    class UnifiedAcl(Base):
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
        ) -> FlextResult[FlextLdapModels.UnifiedAcl]:
            """Create UnifiedAcl instance."""
            # Explicit FlextResult error handling - NO try/except
            return FlextResult.ok(
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
        conditions: FlextTypes.Dict = Field(
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
        ) -> FlextResult[FlextLdapModels.OpenLdapAcl]:
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

                return FlextResult["FlextLdapModels.OpenLdapAcl"].ok(
                    cls(
                        access_line=access_line,
                        target_spec=target_spec,
                        subject_spec=subject_spec or "*",
                        permissions=permissions or "read",
                    )
                )
            except Exception as e:
                return FlextResult["FlextLdapModels.OpenLdapAcl"].fail(
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
        ) -> FlextResult[FlextLdapModels.OracleAcl]:
            """Create OracleAcl from ACI components."""
            try:
                return FlextResult["FlextLdapModels.OracleAcl"].ok(
                    cls(
                        aci_value=aci_value,
                        target_dn=target_dn,
                        subject_spec=subject_spec or "*",
                        permissions=permissions or "read",
                    )
                )
            except Exception as e:
                return FlextResult["FlextLdapModels.OracleAcl"].fail(
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
        ) -> FlextResult[FlextLdapModels.AciFormat]:
            """Create AciFormat from ACI string components."""
            try:
                return FlextResult["FlextLdapModels.AciFormat"].ok(
                    cls(
                        aci_string=aci_string,
                        target=target or "*",
                        subject=subject or "*",
                        permissions=permissions or "read",
                    )
                )
            except Exception as e:
                return FlextResult["FlextLdapModels.AciFormat"].fail(
                    f"Failed to create AciFormat: {e}"
                )

    class ConversionResult(Base):
        """Result of ACL/entry conversion operations."""

        success: bool = Field(..., description="Whether conversion succeeded")
        original_format: str = Field(..., description="Original format type")
        target_format: str = Field(..., description="Target format type")
        converted_data: FlextTypes.Dict = Field(
            default_factory=dict,
            description="Converted data structure",
        )
        errors: list[str] = Field(
            default_factory=list,
            description="Conversion errors/warnings",
        )
        warnings: list[str] = Field(
            default_factory=list,
            description="Conversion warnings",
        )

        @classmethod
        def create(
            cls,
            success: bool,
            original_format: str,
            target_format: str,
            converted_data: FlextTypes.Dict | None = None,
            errors: list[str] | None = None,
            warnings: list[str] | None = None,
        ) -> FlextResult[FlextLdapModels.ConversionResult]:
            """Create ConversionResult from conversion operation."""
            try:
                return FlextResult["FlextLdapModels.ConversionResult"].ok(
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
                return FlextResult["FlextLdapModels.ConversionResult"].fail(
                    f"Failed to create ConversionResult: {e}"
                )


__all__ = [
    "FlextLdapModels",
]

"""Unified LDAP models consolidated into FlextLdapModels.

Consolidates models, entities, and value objects into single class
following one-class-per-module pattern.

Note: Some type checker limitations exist (architectural, no runtime
impact) related to generic type inference and optional overrides.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64
from datetime import datetime
from enum import Enum
from typing import (
    Annotated,
    Any,
    ClassVar,
    Literal,
)

from flext_core import (
    FlextConstants,
    FlextExceptions,
    FlextModels,
    FlextResult,
)
from flext_ldif import FlextLdifModels
from pydantic import (
    BaseModel,
    ConfigDict,
    Discriminator,
    Field,
    SecretStr,
    ValidationInfo,
    computed_field,
    field_serializer,
    model_validator,
)
from pydantic.functional_validators import BeforeValidator

from flext_ldap.constants import (
    AclType,
    FlextLdapConstants,
    ObjectClassKind,
    UpdateStrategy,
)
from flext_ldap.typings import AttributeValue
from flext_ldap.validations import FlextLdapValidations

# ===== PYDANTIC V2 BEFOREVALIDATOR FUNCTIONS =====
# Module-level validators for Pydantic v2 BeforeValidator pattern
# Used with Annotated[type, BeforeValidator(func)] on field annotations


def _validate_dn_format(v: str) -> str:
    """Validate Distinguished Name format (Pydantic v2 BeforeValidator)."""
    if not v or not v.strip():
        msg = "Distinguished Name cannot be empty"
        raise FlextExceptions.ValidationError(msg, field="dn", value=v)

    # Enhanced DN validation - check for proper attribute=value pairs
    if "=" not in v:
        msg = "Invalid DN format - missing attribute=value pairs"
        raise FlextExceptions.ValidationError(msg, field="dn", value=v)

    # Check for valid DN components
    components = v.split(",")
    for comp in components:
        component = comp.strip()
        if "=" not in component:
            msg = f"Invalid DN component: {component}"
            raise FlextExceptions.ValidationError(msg, field="dn", value=component)

        attr, value = component.split("=", 1)
        if not attr.strip() or not value.strip():
            msg = f"Empty attribute or value in DN component: {component}"
            raise FlextExceptions.ValidationError(msg, field="dn", value=component)

    return v.strip()


def _validate_filter_syntax(v: str) -> str:
    """Validate LDAP filter syntax (Pydantic v2 BeforeValidator)."""
    if not v or not v.strip():
        msg = "LDAP filter cannot be empty"
        raise FlextExceptions.ValidationError(msg, field="filter", value=v)
    # Basic filter validation
    if not (v.startswith("(") and v.endswith(")")):
        msg = "LDAP filter must be enclosed in parentheses"
        raise FlextExceptions.ValidationError(msg, field="filter", value=v)
    return v.strip()


def _validate_scope_value(v: str) -> str:
    """Validate LDAP search scope value (Pydantic v2 BeforeValidator)."""
    valid_scopes = {"base", "onelevel", "subtree"}
    if v not in valid_scopes:
        msg = f"Invalid scope: {v}. Must be one of {valid_scopes}"
        raise FlextExceptions.ValidationError(msg, field="scope")
    return v


def _set_defaults_from_constants(v: str | None, info: ValidationInfo) -> str | None:
    """Set defaults from constants for fields if None (Pydantic v2 BeforeValidator)."""
    if v is not None:
        return v or None
    match info.field_name:
        case "department":
            return FlextLdapConstants.Defaults.DEFAULT_DEPARTMENT
        case "title":
            return FlextLdapConstants.Defaults.DEFAULT_TITLE
        case "organization":
            return FlextLdapConstants.Defaults.DEFAULT_ORGANIZATION
        case "status":
            return FlextLdapConstants.Defaults.DEFAULT_STATUS
        case _:
            return None


def _validate_dn_field(v: str) -> str:
    """Validate DN field using centralized validation (Pydantic v2 BeforeValidator)."""
    return FlextLdapValidations.validate_dn_for_field(v)


def _validate_email_field(v: str | None) -> str | None:
    """Validate email field (Pydantic v2 BeforeValidator)."""
    return FlextLdapValidations.validate_email_for_field(v)


def _validate_object_classes_list(v: list[str]) -> list[str]:
    """Validate object classes list (Pydantic v2 BeforeValidator)."""
    if not v:
        msg = "At least one object class is required"
        raise FlextExceptions.ValidationError(msg, field="object_classes", value=str(v))
    return v


def _validate_filter_str(v: str) -> str:
    """Validate LDAP filter format (Pydantic v2 BeforeValidator)."""
    validation_result: FlextResult[None] = FlextLdapValidations.validate_filter(v).map(
        lambda _: None
    )
    if validation_result.is_failure:
        error_msg = validation_result.error or "Filter validation failed"
        raise FlextExceptions.ValidationError(error_msg, field="filter_str", value=v)
    return v.strip()


def _validate_attributes_list(v: list[str] | None) -> list[str] | None:
    """Validate attribute list (Pydantic v2 BeforeValidator)."""
    if v is not None:
        # Remove duplicates and empty strings using set comprehension
        cleaned_attrs = list({attr.strip() for attr in v if attr.strip()})
        return cleaned_attrs or None
    return v


def _set_entries_returned(v: int, info: ValidationInfo) -> int:
    """Auto-calculate entries returned from entries list (Pydantic v2 BeforeValidator)."""
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


def _validate_dn_fields(v: str | None) -> str | None:
    """Validate DN fields (Pydantic v2 BeforeValidator)."""
    if v is not None:
        return FlextLdapValidations.validate_dn_for_field(v)
    return v


def _validate_mail_field(v: str | None) -> str | None:
    """Validate email field (Pydantic v2 BeforeValidator)."""
    if v is None:
        return v
    # Simple email validation
    if "@" not in v:
        msg = f"Invalid email: {v}"
        raise ValueError(msg)
    return v


def _validate_server(v: str) -> str:
    """Validate server hostname/IP (Pydantic v2 BeforeValidator)."""
    return FlextLdapValidations.validate_required_string_for_field(v)


def _validate_port(v: int) -> int:
    """Validate port number (Pydantic v2 BeforeValidator)."""
    if v <= 0 or v > FlextConstants.Network.MAX_PORT:
        msg = f"Port must be between 1 and {FlextConstants.Network.MAX_PORT}"
        raise FlextExceptions.ValidationError(msg, field="port", value=str(v))
    return v


class FlextLdapModels(FlextModels):
    """Unified LDAP models class consolidating models, entities, and values.

    Consolidates previous separate model classes into single unified class:
    - Data models for LDAP operations
    - Domain entities for business logic
    - Value objects for immutable data

    All LDAP data structures available as nested classes within
    FlextLdapModels using Pydantic 2.11 validation features.
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
            "description": "Unified LDAP models with validation",
        },
    )

    # =========================================================================
    # VALIDATOR METHODS - Consolidated from _ValidatorRegistry (Phase 5a)
    # =========================================================================

    @staticmethod
    def validate_dn(value: str | None) -> str | None:
        """Validate DN field - works with Optional strings."""
        return value

    @staticmethod
    def validate_base_dn(value: str) -> str:
        """Validate base DN field."""
        if not value:
            msg = "Base DN cannot be empty"
            raise FlextExceptions.ValidationError(msg, field="base_dn", value=value)
        return value.strip()

    @staticmethod
    def validate_email(value: str | None) -> str | None:
        """Validate email field - optional for most entries."""
        if value is not None:
            # validate_email_for_field raises on failure, returns str | None
            return FlextLdapValidations.validate_email_for_field(value)
        return value

    @staticmethod
    def validate_filter(value: str) -> str:
        """Validate LDAP filter expression."""
        validation_result = FlextLdapValidations.validate_filter(value).map(
            lambda _: None
        )
        if validation_result.is_failure:
            error_msg = validation_result.error or "Filter validation failed"
            raise FlextExceptions.ValidationError(
                error_msg, field="filter_str", value=value
            )
        return value.strip()

    @staticmethod
    def validate_object_classes(value: list[str]) -> list[str]:
        """Validate object classes list."""
        if not value:
            msg = "At least one object class is required"
            raise FlextExceptions.ValidationError(
                msg, field="object_classes", value=str(value)
            )
        return value

    @staticmethod
    def validate_server(value: str) -> str:
        """Validate server hostname/IP."""
        if not value:
            msg = "Server hostname cannot be empty"
            raise FlextExceptions.ValidationError(msg, field="server", value=value)
        return value.strip()

    @staticmethod
    def validate_port(value: int) -> int:
        """Validate port number."""
        if value < 1 or value > FlextLdapConstants.Network.MAX_PORT:
            msg = f"Port must be between 1 and {FlextLdapConstants.Network.MAX_PORT}"
            raise FlextExceptions.ValidationError(msg, field="port", value=str(value))
        return value

    @staticmethod
    def validate_scope(value: str) -> str:
        """Validate LDAP scope."""
        valid_scopes = ("base", "onelevel", "subtree", "BASE", "ONELEVEL", "SUBTREE")
        if value not in valid_scopes:
            msg = f"Scope must be one of {valid_scopes}"
            raise FlextExceptions.ValidationError(msg, field="scope", value=value)
        return value.lower()

    @staticmethod
    def validate_acl_type(value: str) -> str:
        """Validate ACL type."""
        if not value:
            return "auto"
        return value

    # =========================================================================
    # Note: Removed StrictModel and FlexibleModel wrappers
    # Use FlextModels.ArbitraryTypesModel directly with model_config overrides
    # =========================================================================

    # =========================================================================
    # REUSABLE VALIDATORS - Consolidated to reduce duplication
    # =========================================================================

    @staticmethod
    def validate_dn_field(value: str) -> str:
        """Consolidated DN validator used by all request models."""
        return FlextLdapValidations.validate_dn_for_field(value)

    # =========================================================================
    # VALUE OBJECTS - Immutable LDAP value objects
    # =========================================================================

    class DistinguishedName(FlextModels.Value):
        """LDAP Distinguished Name value object with RFC 2253 compliance.

        Extends FlextValue for immutable value object behavior with strict validation.
        Uses Pydantic 2.11 features for LDAP-specific validation.
        """

        value: Annotated[str, BeforeValidator(_validate_dn_format)] = Field(
            ...,
            min_length=1,
            description="Distinguished Name string",
            pattern=r"^[a-zA-Z]+=.+",  # Basic DN pattern
            examples=[
                "cn=John Doe,ou=users,dc=example,dc=com",
                "uid=REDACTED_LDAP_BIND_PASSWORD,dc=ldap,dc=local",
            ],
        )

        @model_validator(mode="after")
        def validate_dn_structure(self) -> FlextLdapModels.DistinguishedName:
            """Cross-field validation for DN structure integrity."""
            # Validate DN has at least one component
            components = self.value.split(",")
            if len(components) < 1:
                error_msg = "DN must have at least one component"
                raise FlextExceptions.ValidationError(
                    error_msg,
                    field="dn",
                    value=self.value,
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
                        raise FlextExceptions.ValidationError(
                            error_msg,
                            field="rdn",
                            value=attr,
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
            components: list[str] = []
            for comp in value.split(","):
                component = comp.strip()
                if "=" in component:
                    attr, val = component.split("=", 1)
                    # Normalize attribute name to lowercase, preserve value case
                    normalized_component = f"{attr.strip().lower()}={val.strip()}"
                    components.append(normalized_component)
            return ",".join(components)

        @classmethod
        def create(
            cls, *args: object, **kwargs: object
        ) -> FlextResult[FlextLdapModels.DistinguishedName]:
            """Create DN with validation - compatible with base class signature."""
            try:
                # Handle single argument case for DN string
                if len(args) == 1 and not kwargs:
                    dn_string = str(args[0])
                    dn_obj = cls(value=dn_string.strip())
                    return FlextResult[FlextLdapModels.DistinguishedName].ok(dn_obj)

                # Handle kwargs case - ensure value is string
                if "value" in kwargs:
                    kwargs["value"] = str(kwargs["value"])

                # Convert all kwargs to proper types for Pydantic validation
                typed_kwargs: dict[str, str] = {}
                for k, v in kwargs.items():
                    typed_kwargs[k] = str(v)

                dn_obj = cls(**typed_kwargs)
                return FlextResult[FlextLdapModels.DistinguishedName].ok(dn_obj)
            except FlextExceptions.ValidationError as e:
                return FlextResult[FlextLdapModels.DistinguishedName].fail(
                    f"DN creation failed: {e}",
                )
            except Exception as e:
                return FlextResult[FlextLdapModels.DistinguishedName].fail(
                    f"DN creation failed: {e}",
                )

    class Filter(FlextModels.Value):
        """LDAP filter value object with RFC 4515 compliance.

        Extends FlextModels.Value for proper Pydantic 2 validation and composition.
        """

        expression: Annotated[str, BeforeValidator(_validate_filter_syntax)] = Field(
            ..., min_length=1, description="LDAP filter expression"
        )

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

        value: Annotated[str, BeforeValidator(_validate_scope_value)] = Field(
            ..., description="LDAP search scope value"
        )

        BASE: ClassVar[str] = "base"
        ONELEVEL: ClassVar[str] = "onelevel"
        SUBTREE: ClassVar[str] = "subtree"

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
        superior: list[str] = Field(
            default_factory=list,
            description="Superior classes",
        )
        must: list[str] = Field(
            default_factory=list,
            description="Required attributes",
        )
        may: list[str] = Field(
            default_factory=list,
            description="Optional attributes",
        )
        kind: str = Field(default="STRUCTURAL", description="Object class kind")
        is_obsolete: bool = Field(default=False, description="Obsolete flag")

    class ServerQuirks(FlextModels.Value):
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
        attribute_name_mappings: dict[str, str] = Field(default_factory=dict)
        object_class_mappings: dict[str, str] = Field(default_factory=dict)
        dn_format_preferences: list[str] = Field(default_factory=list)
        search_scope_limitations: set[str] = Field(default_factory=set)
        filter_syntax_quirks: list[str] = Field(default_factory=list)
        modify_operation_quirks: list[str] = Field(default_factory=list)

    class SchemaDiscoveryResult(FlextModels.Entity):
        """Result of LDAP schema discovery operation - Pydantic Entity."""

        # Note: Cannot use frozen=True with Entity (has default timestamp fields)

        server_info: FlextLdapModels.ServerInfo
        server_type: FlextLdapModels.LdapServerType
        server_quirks: FlextLdapModels.ServerQuirks
        attributes: dict[str, FlextLdapModels.SchemaAttribute]
        object_classes: dict[str, FlextLdapModels.SchemaObjectClass]
        naming_contexts: list[str]
        supported_controls: list[str]
        supported_extensions: list[str]

    # =========================================================================
    # BASE CLASSES - Common functionality for LDAP entities
    # =========================================================================

    class Base(FlextModels.ArbitraryTypesModel):
        """Base model - dynamic LDAP schema support.

        DYNAMIC LDAP SCHEMA: Accepts arbitrary attributes for varying
        server schemas (OpenLDAP, AD, OID/OUD, 389 DS, etc.)
        """

        model_config = ConfigDict(extra="allow")

        # LDAP-specific timestamp fields (nullable)
        created_at: datetime | None = Field(
            default=None,
            description="Creation timestamp",
        )
        updated_at: datetime | None = Field(
            default=None,
            description="Last update timestamp",
        )

    class EntityBase(FlextModels.Entity):
        """Base class for LDAP entities with common fields and validation.

        Provides common fields and validation methods that are shared
        across multiple LDAP entity types.
        """

        # Common additional attributes field
        additional_attributes: dict[
            str,
            AttributeValue,
        ] = Field(
            default_factory=dict,
            description="Additional LDAP attributes",
        )

    # =========================================================================
    # CORE LDAP ENTITIES - Primary Domain Objects (Consolidated into Entry)
    # =========================================================================
    # Note: LdapUser and Group classes have been consolidated into the unified
    # polymorphic Entry model using Pydantic 2.11 discriminated unions.
    # All functionality is now available through FlextLdapModels.Entry with
    # entry_type discriminator (user, group, organizationalUnit, device, etc.)

    class Entry(EntityBase):
        """Unified polymorphic LDAP Entry combining User, Group, generic types.

        Centralized model: entry_type discriminator for user/group/etc.
        Type-aware validation via Pydantic 2.11 discriminated unions.
        Python 3.13+ modern syntax with automatic field routing.
        """

        # Discriminator for polymorphic union - Pydantic 2.11 feature
        entry_type: Literal[
            "user",
            "group",
            "organizationalUnit",
            "device",
            "organizationalRole",
            "entry",
        ] = Field(
            default="entry",
            description="Entry type discriminator for polymorphic routing",
        )

        # =====================================================================
        # COMMON FIELDS (all entry types)
        # =====================================================================

        # Core identification
        dn: Annotated[str, BeforeValidator(_validate_dn_field)] = Field(
            ..., description="Distinguished Name (unique identifier)"
        )
        cn: str | None = Field(default=None, description="Common Name")

        # LDAP metadata
        object_classes: Annotated[
            list[str], BeforeValidator(_validate_object_classes_list)
        ] = Field(
            default_factory=list,
            description="LDAP object classes",
        )

        # Core fields
        status: Annotated[str | None, BeforeValidator(_set_defaults_from_constants)] = (
            Field(default=None, description="Entry status (active/disabled/etc)")
        )
        additional_attributes: dict[
            str,
            AttributeValue,
        ] = Field(
            default_factory=dict,
            description="Additional LDAP attributes",
        )
        display_name: str | None = Field(default=None, description="Display Name")
        modified_at: str | None = Field(
            default=None, description="Last modification timestamp (string)"
        )
        created_timestamp: datetime | None = Field(
            default=None, description="Creation timestamp"
        )
        modified_timestamp: datetime | None = Field(
            default=None, description="Modification timestamp"
        )

        # =====================================================================
        # USER-SPECIFIC FIELDS (Optional for other entry types)
        # =====================================================================

        uid: str | None = Field(default=None, description="User ID (uid attribute)")
        sn: str | None = Field(default=None, description="Surname (sn attribute)")
        given_name: str | None = Field(
            default=None, description="Given Name (givenName attribute)"
        )
        mail: Annotated[str | None, BeforeValidator(_validate_email_field)] = Field(
            default=None, description="Primary email address"
        )
        telephone_number: str | None = Field(
            default=None, description="Primary phone number"
        )
        mobile: str | None = Field(default=None, description="Mobile phone number")
        department: Annotated[
            str | None, BeforeValidator(_set_defaults_from_constants)
        ] = Field(default=None, description="Department")
        title: Annotated[str | None, BeforeValidator(_set_defaults_from_constants)] = (
            Field(default=None, description="Job title")
        )
        organization: Annotated[
            str | None, BeforeValidator(_set_defaults_from_constants)
        ] = Field(default=None, description="Organization (o attribute)")
        organizational_unit: str | None = Field(
            default=None, description="Organizational Unit (ou attribute)"
        )
        user_password: str | SecretStr | None = Field(
            default=None, description="User password (protected)"
        )

        # =====================================================================
        # GROUP-SPECIFIC FIELDS (Optional for other entry types)
        # =====================================================================

        gid_number: int | None = Field(
            default=None, description="Group ID Number (gidNumber attribute)"
        )
        member_dns: list[str] = Field(
            default_factory=list,
            description="Member Distinguished Names (member attribute)",
        )
        unique_member_dns: list[str] = Field(
            default_factory=list,
            description="Unique Member Distinguished Names (uniqueMember attribute)",
        )
        description: str | None = Field(default=None, description="Entry description")

        # =====================================================================
        # GENERIC ENTRY FIELDS (for unstructured attribute access)
        # =====================================================================

        attributes: dict[str, AttributeValue] = Field(
            default_factory=dict,
            description="LDAP entry attributes (for generic/unstructured entries)",
        )

        @field_serializer("user_password")
        def serialize_password(self, value: str | SecretStr | None) -> str | None:
            """Field serializer for password handling - protect sensitive data."""
            if value is None:
                return None
            if isinstance(value, SecretStr):
                return "[PROTECTED]"
            return "[PROTECTED]" if value else None

        @field_serializer("dn")
        def serialize_dn(self, value: str) -> str:
            """Field serializer for DN normalization."""
            components = [component.strip() for component in value.split(",")]
            return ",".join(components)

        # =====================================================================
        # COMPUTED FIELDS (Type-aware, only calculate for relevant entry types)
        # =====================================================================

        @computed_field
        def full_name(self) -> str | None:
            """Full name for user entries: givenName sn → givenName → sn → cn."""
            if self.entry_type != "user":
                return None
            match (self.given_name, self.sn):
                case (given, sn) if given and sn:
                    return f"{given} {sn}"
                case (given, _) if given:
                    return given
                case (_, sn) if sn:
                    return sn
                case _:
                    return self.cn

        @computed_field
        def is_active(self) -> bool:
            """Active if status is None or 'active', not 'disabled' (user entries)."""
            if self.entry_type != "user":
                return (
                    self.status in {None, "active"} or (self.status or "") != "disabled"
                )
            return self.status in {None, "active"} or self.status != "disabled"

        @computed_field
        def has_contact_info(self) -> bool:
            """User has email AND (phone OR mobile) - user entries only."""
            if self.entry_type != "user":
                return False
            return bool(self.mail and (self.telephone_number or self.mobile))

        @computed_field
        def organizational_path(self) -> str | None:
            """Full org hierarchy: org > ou > dept - user entries only."""
            if self.entry_type != "user":
                return None
            parts = [
                p
                for p in [self.organization, self.organizational_unit, self.department]
                if p
            ]
            return " > ".join(parts) if parts else "No organization"

        @computed_field
        def rdn(self) -> str:
            """Computed field for Relative Distinguished Name (all entries)."""
            return self.dn.split(",")[0] if "," in self.dn else self.dn

        @computed_field
        def has_members(self) -> bool:
            """Group has members - group entries only."""
            if self.entry_type != "group":
                return False
            return bool(self.member_dns or self.unique_member_dns)

        @model_validator(mode="after")
        def validate_entry_consistency(self) -> FlextLdapModels.Entry:
            """Model validator for polymorphic validation and business rules."""
            match self.entry_type:
                case "user":
                    # User entries must have person object class
                    if "person" not in self.object_classes:
                        msg = "User must have 'person' object class"
                        raise FlextExceptions.ValidationError(
                            msg,
                            field="object_classes",
                            value=str(self.object_classes),
                        )
                    # Set display_name from cn if not provided
                    if not self.display_name and self.cn:
                        self.display_name = self.cn
                    # Validate organizational consistency
                    if (
                        self.department
                        and self.department
                        != FlextLdapConstants.Defaults.DEFAULT_DEPARTMENT
                        and not self.organizational_unit
                    ):
                        msg = "Department requires organizational unit"
                        raise FlextExceptions.ValidationError(
                            msg,
                            field="department",
                            value=str(self.department),
                        )

                case "group":
                    # Group entries must have a valid group object class
                    valid_group_classes = {
                        "groupOfNames",
                        "groupOfUniqueNames",
                        "posixGroup",
                    }
                    if not any(
                        cls in self.object_classes for cls in valid_group_classes
                    ):
                        msg = (
                            f"Group must have one of {valid_group_classes} object class"
                        )
                        raise FlextExceptions.ValidationError(
                            msg,
                            field="object_classes",
                            value=str(self.object_classes),
                        )

            return self

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate entry business rules with polymorphic error handling."""
            match self.entry_type:
                case "user":
                    if "person" not in self.object_classes:
                        return FlextResult[None].fail(
                            "User must have 'person' object class"
                        )
                    if not self.cn:
                        return FlextResult[None].fail("User must have a Common Name")

                case "group":
                    valid_group_classes = {
                        "groupOfNames",
                        "groupOfUniqueNames",
                        "posixGroup",
                    }
                    if not any(
                        cls in self.object_classes for cls in valid_group_classes
                    ):
                        return FlextResult[None].fail(
                            f"Group must have one of {valid_group_classes} object class"
                        )

            return FlextResult[None].ok(None)

        def to_ldap_attributes(self) -> dict[str, list[str]]:
            """Convert entry to LDAP attributes (polymorphic based on entry_type)."""
            attrs: dict[str, list[str]] = {}

            # Common attributes
            if self.dn:
                attrs["dn"] = [self.dn]
            if self.cn:
                attrs["cn"] = [self.cn]
            if self.object_classes:
                attrs["objectClass"] = self.object_classes
            if self.description:
                attrs["description"] = [self.description]

            # Type-specific attributes
            match self.entry_type:
                case "user":
                    if self.uid:
                        attrs["uid"] = [self.uid]
                    if self.sn:
                        attrs["sn"] = [self.sn]
                    if self.given_name:
                        attrs["givenName"] = [self.given_name]
                    if self.mail:
                        attrs["mail"] = [self.mail]
                    if self.telephone_number:
                        attrs["telephoneNumber"] = [self.telephone_number]
                    if self.mobile:
                        attrs["mobile"] = [self.mobile]
                    if self.department:
                        attrs["department"] = [self.department]
                    if self.title:
                        attrs["title"] = [self.title]
                    if self.organization:
                        attrs["o"] = [self.organization]
                    if self.organizational_unit:
                        attrs["ou"] = [self.organizational_unit]

                case "group":
                    if self.gid_number:
                        attrs["gidNumber"] = [str(self.gid_number)]
                    if self.member_dns:
                        attrs["member"] = self.member_dns
                    if self.unique_member_dns:
                        attrs["uniqueMember"] = self.unique_member_dns

            # Add additional attributes for all types
            if self.additional_attributes:
                for k, v in self.additional_attributes.items():
                    attrs[k] = [str(x) for x in v] if isinstance(v, list) else [str(v)]

            return attrs

        @classmethod
        def from_ldap_attributes(
            cls,
            ldap_attributes: dict[str, list[str]],
            entry_type: str | None = None,
        ) -> FlextResult[FlextLdapModels.Entry]:
            """Create entry from LDAP attributes with polymorphic auto-detect."""
            dn_vals = ldap_attributes.get(FlextLdapConstants.LdapAttributeNames.DN, [])
            if not dn_vals:
                return FlextResult[FlextLdapModels.Entry].fail("DN is required")

            # Helper to extract first attribute value
            def _attr(k: str) -> str | None:
                v = ldap_attributes.get(k)
                return v[0] if v else None

            # Auto-detect entry_type if not provided
            detected_type = entry_type or "entry"
            obj_classes = set(
                ldap_attributes.get(
                    FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS, []
                )
            )
            if not entry_type:
                if "person" in obj_classes or "inetOrgPerson" in obj_classes:
                    detected_type = "user"
                elif (
                    "groupOfNames" in obj_classes
                    or "groupOfUniqueNames" in obj_classes
                    or "posixGroup" in obj_classes
                ):
                    detected_type = "group"
                # Additional detection based on attributes if objectClass not present
                elif not obj_classes:
                    # Check for user-specific attributes
                    if FlextLdapConstants.LdapAttributeNames.UID in ldap_attributes:
                        detected_type = "user"
                    # Check for group-specific attributes
                    elif (
                        FlextLdapConstants.LdapAttributeNames.GID_NUMBER
                        in ldap_attributes
                        or FlextLdapConstants.LdapAttributeNames.MEMBER
                        in ldap_attributes
                    ):
                        detected_type = "group"

            # Build kwargs with default object_classes based on entry type
            if obj_classes:
                default_object_classes = list(obj_classes)
            else:
                match detected_type:
                    case "user":
                        default_object_classes = ["person", "inetOrgPerson", "top"]
                    case "group":
                        default_object_classes = ["groupOfNames", "top"]
                    case _:
                        default_object_classes = ["top"]

            entry_data: dict[str, object] = {
                "entry_type": detected_type,
                "dn": dn_vals[0],
                "cn": _attr(FlextLdapConstants.LdapAttributeNames.CN),
                "status": "active",
                "object_classes": default_object_classes,
                "additional_attributes": {},
            }

            # Type-specific attributes
            match detected_type:
                case "user":
                    entry_data.update({
                        "uid": _attr(FlextLdapConstants.LdapAttributeNames.UID) or "",
                        "sn": _attr(FlextLdapConstants.LdapAttributeNames.SN) or "",
                        "given_name": _attr(
                            FlextLdapConstants.LdapAttributeNames.GIVEN_NAME
                        ),
                        "mail": _attr(FlextLdapConstants.LdapAttributeNames.MAIL),
                        "telephone_number": _attr(
                            FlextLdapConstants.LdapAttributeNames.TELEPHONE_NUMBER
                        ),
                        "mobile": _attr(FlextLdapConstants.LdapAttributeNames.MOBILE),
                        "department": _attr(
                            FlextLdapConstants.LdapAttributeNames.DEPARTMENT
                        ),
                        "title": _attr(FlextLdapConstants.LdapAttributeNames.TITLE),
                        "organization": _attr("o"),
                        "organizational_unit": _attr(
                            FlextLdapConstants.LdapAttributeNames.OU
                        ),
                        "display_name": _attr(FlextLdapConstants.LdapAttributeNames.CN)
                        or "",
                    })

                case "group":
                    gid_vals = ldap_attributes.get(
                        FlextLdapConstants.LdapAttributeNames.GID_NUMBER, []
                    )
                    entry_data.update({
                        "gid_number": int(gid_vals[0]) if gid_vals else None,
                        "description": _attr(
                            FlextLdapConstants.LdapAttributeNames.DESCRIPTION
                        ),
                        "member_dns": ldap_attributes.get(
                            FlextLdapConstants.LdapAttributeNames.MEMBER, []
                        ),
                        "unique_member_dns": ldap_attributes.get(
                            FlextLdapConstants.LdapAttributeNames.UNIQUE_MEMBER,
                            [],
                        ),
                    })

            try:
                # Cast entry_data from dict[str, object] to Any to allow unpacking
                # The dictionary is built correctly above with proper types
                from typing import cast

                entry = cls(**cast("dict[str, Any]", entry_data))
                return FlextResult[FlextLdapModels.Entry].ok(entry)
            except Exception as e:
                return FlextResult[FlextLdapModels.Entry].fail(
                    f"Failed to create entry from LDAP attributes: {e}"
                )

        @classmethod
        def create_minimal(
            cls,
            dn: str,
            cn: str,
            entry_type: str = "entry",
            **kwargs: object,
        ) -> FlextResult[FlextLdapModels.Entry]:
            """Create minimal valid entry with required fields only."""
            try:
                entry_data: dict[str, object] = {
                    "entry_type": entry_type,
                    "dn": dn,
                    "cn": cn,
                    "status": "active",
                }

                # Type-specific minimal data
                match entry_type:
                    case "user":
                        user_data: dict[str, object] = {
                            "uid": kwargs.get("uid") or "",
                            "sn": kwargs.get("sn") or "",
                            "object_classes": [
                                "person",
                                "organizationalPerson",
                                "inetOrgPerson",
                            ],
                        }
                        # Add optional fields if provided
                        optional_fields = [
                            "mail",
                            "given_name",
                            "telephone_number",
                            "mobile",
                            "department",
                            "title",
                            "organization",
                            "organizational_unit",
                            "user_password",
                            "display_name",
                        ]
                        for field in optional_fields:
                            if kwargs.get(field):
                                user_data[field] = kwargs[field]
                        entry_data.update(user_data)

                    case "group":
                        entry_data.update({
                            "member_dns": [],
                            "unique_member_dns": [],
                            "object_classes": ["groupOfNames", "top"],
                        })

                    case _:
                        entry_data["object_classes"] = ["top"]

                # Cast entry_data from dict[str, object] to Any to allow unpacking
                # The dictionary is built correctly above with proper types
                from typing import cast

                entry = cls(**cast("dict[str, Any]", entry_data))
                return FlextResult[FlextLdapModels.Entry].ok(entry)
            except Exception as e:
                return FlextResult[FlextLdapModels.Entry].fail(
                    f"Failed to create minimal entry: {e}"
                )

        # =====================================================================
        # GROUP-SPECIFIC METHODS (only meaningful for group entries)
        # =====================================================================

        def has_member(self, member_dn: str) -> bool:
            """Check if DN is a member of this group (group entries only)."""
            if self.entry_type != "group":
                return False
            return member_dn in self.member_dns or member_dn in self.unique_member_dns

        def add_member(self, member_dn: str) -> FlextResult[None]:
            """Add member to group (group entries only)."""
            if self.entry_type != "group":
                return FlextResult[None].fail("add_member only valid for group entries")
            if member_dn not in self.member_dns:
                self.member_dns.append(member_dn)
            return FlextResult[None].ok(None)

        def remove_member(self, member_dn: str) -> FlextResult[None]:
            """Remove member from group (group entries only)."""
            if self.entry_type != "group":
                return FlextResult[None].fail(
                    "remove_member only valid for group entries"
                )
            if member_dn in self.member_dns:
                self.member_dns.remove(member_dn)
                return FlextResult[None].ok(None)
            return FlextResult[None].fail(f"Member {member_dn} not found in group")

        # =====================================================================
        # GENERIC ENTRY METHODS (dict-like interface and utilities)
        # =====================================================================

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists."""
            return name in self.attributes

        def __getitem__(
            self,
            key: str,
        ) -> AttributeValue | dict[str, AttributeValue] | None:
            """Dict-like access to attributes."""
            if key == "dn":
                return self.dn
            if key == "attributes":
                return self.attributes
            if key in {"objectClass", "objectClasses"}:
                return self.object_classes
            return self.attributes.get(key)

        def __contains__(self, key: str) -> bool:
            """Dict-like containment check."""
            if not isinstance(key, str):
                return False
            if key == "dn":
                return self.dn is not None
            if key == "attributes":
                return bool(self.attributes)
            if key in {"objectClass", "objectClasses"}:
                return self.object_classes is not None
            return self.has_attribute(key)

        def get(
            self,
            key: str,
            default: (AttributeValue | dict[str, AttributeValue] | None) = None,
        ) -> AttributeValue | dict[str, AttributeValue] | None:
            """Dict-like get method with default value."""
            if key == "dn":
                return self.dn or default
            if key == "attributes":
                return self.attributes or default
            if key in {"objectClass", "objectClasses"}:
                return self.object_classes or default
            return self.attributes.get(key, default)

        def get_attribute(self, name: str) -> AttributeValue | None:
            """Get a single attribute value by name."""
            return self.attributes.get(name)

        def set_attribute(self, name: str, value: AttributeValue) -> None:
            """Set a single attribute value by name."""
            self.attributes[name] = value

        def get_rdn(self) -> str:
            """Get the Relative Distinguished Name (RDN) from the DN."""
            dn_str = str(self.dn) if not isinstance(self.dn, str) else self.dn
            return dn_str.split(",", maxsplit=1)[0]

        @classmethod
        def from_ldif(cls, ldif_entry: FlextLdifModels.Entry) -> FlextLdapModels.Entry:
            """Convert FlextLdif Entry to FlextLdap Entry using adapter pattern."""
            if not hasattr(ldif_entry, "dn") or not hasattr(ldif_entry, "attributes"):
                msg = "Invalid LDIF entry: missing dn or attributes"
                raise ValueError(msg)

            return cls(
                dn=str(ldif_entry.dn),
                attributes=dict(ldif_entry.attributes),
                entry_type="entry",
            )

        def to_ldif(self) -> FlextLdifModels.Entry:
            """Convert FlextLdap Entry to FlextLdif Entry using adapter pattern."""
            dn_value: FlextLdifModels.DistinguishedName
            if isinstance(self.dn, str):
                dn_value = FlextLdifModels.DistinguishedName(value=self.dn)
            else:
                dn_value = FlextLdifModels.DistinguishedName(value=str(self.dn))

            ldif_attributes: dict[str, FlextLdifModels.AttributeValues] = {}
            for attr_name, attr_values in self.attributes.items():
                if isinstance(attr_values, str):
                    ldif_attributes[attr_name] = FlextLdifModels.AttributeValues(
                        values=[attr_values],
                    )
                elif isinstance(attr_values, list):
                    ldif_attributes[attr_name] = FlextLdifModels.AttributeValues(
                        values=[str(v) for v in attr_values],
                    )
                else:
                    ldif_attributes[attr_name] = FlextLdifModels.AttributeValues(
                        values=[str(attr_values)],
                    )

            return FlextLdifModels.Entry(
                dn=dn_value,
                attributes=FlextLdifModels.LdifAttributes(attributes=ldif_attributes),
            )

    # =========================================================================
    # LDAP OPERATION ENTITIES - Request/Response Objects
    # =========================================================================

    class SearchRequest(BaseModel):
        """LDAP Search Request with parameters and Pydantic 2.11 validation."""

        # Default attribute constants
        DEFAULT_USER_ATTRIBUTES: ClassVar[list[str]] = [
            "uid",
            "cn",
            "sn",
            "mail",
            "objectClass",
        ]
        DEFAULT_GROUP_ATTRIBUTES: ClassVar[list[str]] = [
            "cn",
            "member",
            "description",
            "objectClass",
        ]

        @classmethod
        def get_user_attributes(cls) -> list[str]:
            """Get default user attributes for search requests.

            Returns:
            List of default user attributes.

            """
            return cls.DEFAULT_USER_ATTRIBUTES.copy()

        # Search scope
        base_dn: Annotated[str, BeforeValidator(_validate_dn_field)] = Field(
            ..., description="Search base Distinguished Name"
        )
        filter_str: Annotated[str, BeforeValidator(_validate_filter_str)] = Field(
            ..., description="LDAP search filter"
        )
        scope: str = Field(
            default="subtree",
            description="Search scope: base, onelevel, subtree",
            pattern="^(base|onelevel|subtree|BASE|ONELEVEL|SUBTREE)$",
        )

        # Attribute selection
        attributes: Annotated[
            list[str] | None, BeforeValidator(_validate_attributes_list)
        ] = Field(
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

        # Additional options
        types_only: bool = Field(
            default=False,
            description="Return attribute types only (no values)",
        )
        deref_aliases: str = Field(
            default="never",
            description="Alias dereferencing: never, searching, finding, always",
            pattern="^(never|searching|finding|always)$",
        )

        @model_validator(mode="after")
        def validate_search_consistency(self) -> FlextLdapModels.SearchRequest:
            """Model validator for cross-field validation and search optimization."""
            max_time_limit_seconds = 300  # 5 minutes maximum
            max_page_multiplier = 100  # Maximum page size multiplier

            # Validate paging consistency
            if self.page_size is not None and self.page_size <= 0:
                msg = "Page size must be positive if specified"
                raise FlextExceptions.ValidationError(
                    msg,
                    field="page_size",
                    value=str(self.page_size),
                )

            # Optimize size limit for paged searches
            if (
                self.page_size is not None
                and self.page_size > 0
                and self.size_limit > self.page_size * max_page_multiplier
            ):
                # Automatically adjust size limit for very large paged searches
                self.size_limit = min(
                    self.size_limit,
                    self.page_size * max_page_multiplier,
                )

            # Validate time limit is reasonable
            if self.time_limit > max_time_limit_seconds:
                msg = f"Time limit exceeds {max_time_limit_seconds} seconds"
                raise FlextExceptions.ValidationError(
                    msg,
                    field="time_limit",
                    value=str(self.time_limit),
                )

            # (objectClass=*) valid for BASE scope; retrieves entry at base DN

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
            attributes: list[str] | None = None,
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
            attributes: list[str] | None = None,
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
            filter_str: str,
            scope: str = "subtree",
            attributes: list[str] | None = None,
        ) -> FlextLdapModels.SearchRequest:
            """Factory method with smart defaults from FlextLdapConstants.

            Creates a SearchRequest with intelligent defaults for common parameters,
            eliminating the need to specify page_size, paged_cookie, and other
            boilerplate parameters.

            Args:
                base_dn: Search base Distinguished Name
                filter_str: LDAP search filter (required)
                scope: Search scope (default: SUBTREE from FlextLdapConstants)
                attributes: Attributes to retrieve (empty list = all)

            Returns:
                FlextLdapModels.SearchRequest: Configured request with smart defaults

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

                # Factory method with smart defaults
                req = FlextLdapModels.SearchRequest.create(
                    base_dn, filter_str, scope, attributes
                )

            """
            return cls.model_validate({
                "base_dn": base_dn,
                "filter_str": filter_str,
                "scope": scope,
                "attributes": attributes or [],
                "page_size": FlextConstants.Performance.DEFAULT_PAGE_SIZE,
                "paged_cookie": b"",
                "size_limit": (
                    FlextConstants.Performance.BatchProcessing.MAX_VALIDATION_SIZE
                ),
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

    class SearchResponse(BaseModel):
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
        entries_returned: Annotated[int, BeforeValidator(_set_entries_returned)] = (
            Field(
                default=0,
                description="Number of entries returned",
            )
        )
        time_elapsed: float = Field(default=0.0, description="Search time in seconds")

    # =========================================================================
    # GENERIC LDAP REQUEST - Consolidated factory-based implementation
    # Consolidates 9+ request types (Update/Upsert/Create operations)
    # Python 3.13+ with TypeAlias for backward compatibility
    # =========================================================================

    class _LdapRequest(BaseModel):
        """Universal LDAP request - consolidated from 12+ request classes.

        Composition-based consolidation: Entry, User, Group, ACL, Schema operations.
        Eliminates 450+ lines of duplication across specialized request classes.

        Supports:
        - Add/Update/Upsert entry operations
        - Create/Update/Upsert ACL operations
        - Create/Update/Upsert schema operations
        - Create user/group operations
        """

        # Core DN fields
        dn: Annotated[str | None, BeforeValidator(_validate_dn_fields)] = Field(
            default=None, description="Distinguished Name"
        )
        schema_dn: Annotated[str | None, BeforeValidator(_validate_dn_fields)] = Field(
            default=None, description="DN of schema subentry"
        )

        # General attributes (for Add, Update, Upsert operations)
        attributes: dict[str, str | list[str]] | None = Field(
            default=None, description="Entry attributes"
        )
        object_classes: list[str] | None = Field(
            default=None, description="LDAP object classes"
        )

        # User/Group specific fields
        cn: str | None = Field(default=None, description="Common Name")
        sn: str | None = Field(default=None, description="Surname")
        uid: str | None = Field(default=None, description="User ID")
        given_name: str | None = Field(default=None, description="Given Name")
        user_password: str | None = Field(default=None, description="User password")
        mail: Annotated[str | None, BeforeValidator(_validate_mail_field)] = Field(
            default=None, description="Email address"
        )
        owner: str | None = Field(default=None, description="Group owner")
        member: list[str] = Field(default_factory=list, description="Group members")

        # ACL operations
        acl_rules: list[str] | None = Field(default=None, description="ACL rules")
        acl_type: AclType = "auto"

        # Schema attribute fields
        name: str | None = Field(default=None, description="Schema element name")
        syntax: str | None = Field(default=None, description="LDAP syntax OID")
        single_value: bool = False
        equality_match: str | None = None
        ordering_match: str | None = None
        substr_match: str | None = None

        # Schema changes/elements
        changes: dict[str, str | list[str]] | None = Field(
            default=None, description="Schema changes"
        )
        schema_element: dict[str, str | list[str]] | None = Field(
            default=None, description="Schema element"
        )

        # Object class definition fields
        must_attributes: list[str] = Field(
            default_factory=list, description="MUST attributes"
        )
        may_attributes: list[str] = Field(
            default_factory=list, description="MAY attributes"
        )
        parent: str | None = "top"
        kind: ObjectClassKind = "STRUCTURAL"

        # Update/Upsert strategies
        strategy: UpdateStrategy = "merge"
        update_strategy: UpdateStrategy = "merge"

        # General fields
        description: str | None = None
        server_type: str | None = None

        # User-specific fields (consolidated for User create/update operations)
        telephone_number: str | None = None
        department: str | None = None
        title: str | None = None
        organization: str | None = None
        organizational_unit: str | None = None
        mobile: str | None = None

        def to_attributes(self) -> dict[str, str | list[str]]:
            """Convert request to LDAP attributes dict."""
            if self.attributes:
                return self.attributes

            # Build from individual fields (for user/group creation)
            attrs: dict[str, str | list[str]] = {}
            if self.cn:
                attrs["cn"] = [self.cn]
            if self.sn:
                attrs["sn"] = [self.sn]
            if self.uid:
                attrs["uid"] = [self.uid]
            if self.given_name:
                attrs["givenName"] = [self.given_name]
            if self.mail:
                attrs["mail"] = [self.mail]
            if self.description:
                attrs["description"] = [self.description]
            if self.owner:
                attrs["owner"] = [self.owner]
            if self.member:
                attrs["member"] = self.member
            if self.object_classes:
                attrs["objectClass"] = self.object_classes
            return attrs

    # =========================================================================
    # CONSOLIDATED SYNC RESULT - Python 3.13+ composition pattern
    # Consolidates SyncResult, AclSyncResult, SchemaSyncResult into one generic class
    # =========================================================================

    class SyncResult(BaseModel):
        """Generic result model for sync operations using composition.

        Consolidates base sync tracking with ACL and Schema-specific fields.
        All operation-specific fields are optional for flexibility.
        Reduces 64 lines to ~40 lines through aggressive consolidation.

        Supports:
        - Entry sync operations
        - ACL sync operations with format conversion tracking
        - Schema sync operations with attribute/class tracking
        """

        # Core sync statistics (used by all operation types)
        created: int = Field(default=0, description="Number of items created")
        updated: int = Field(default=0, description="Number of items updated")
        deleted: int = Field(default=0, description="Number of items deleted")
        failed: int = Field(default=0, description="Number of failed operations")
        errors: list[str] = Field(
            default_factory=list, description="Error messages from failed operations"
        )
        operations: list[dict[str, str]] = Field(
            default_factory=list, description="Detailed operation log"
        )

        # ACL sync specific fields (optional for composition)
        acls_converted: int = Field(
            default=0, description="Number of ACLs converted between formats"
        )
        server_types_detected: list[str] = Field(
            default_factory=list, description="Server types detected during sync"
        )

        # Schema sync specific fields (optional for composition)
        attributes_created: int = Field(
            default=0, description="Number of schema attributes created"
        )
        object_classes_created: int = Field(
            default=0, description="Number of object classes created"
        )
        schema_conflicts: list[str] = Field(
            default_factory=list, description="Schema conflicts encountered"
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
    # CONNECTION AND CONFIGURATION ENTITIES
    # =========================================================================

    class ConnectionInfo(BaseModel):
        """LDAP Connection Information entity."""

        # Connection details
        server: Annotated[str, BeforeValidator(_validate_server)] = Field(
            default="localhost", description="LDAP server hostname/IP"
        )
        port: Annotated[int, BeforeValidator(_validate_port)] = Field(
            FlextLdapConstants.Protocol.DEFAULT_PORT,
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

    # =========================================================================
    # ERROR AND STATUS ENTITIES
    # =========================================================================

    class LdapOperationResult(BaseModel):
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
        data: dict[str, object] = Field(
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
            data: dict[str, object] | None = None,
            duration_ms: float = 0.0,
        ) -> FlextLdapModels.LdapOperationResult:
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
        ) -> FlextLdapModels.LdapOperationResult:
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

        server: str
        port: int = FlextLdapConstants.Protocol.DEFAULT_PORT
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

    class SearchConfig(FlextModels.Query):
        """LDAP search operation configuration - Pydantic Query."""

        model_config = ConfigDict(frozen=True)

        base_dn: str
        filter_str: str
        attributes: list[str]

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
    # ACL TARGET AND SUBJECT MODELS - Access Control List components
    # =========================================================================

    class AclTarget(BaseModel):
        """ACL target specification for access control rules."""

        target_type: str = Field(
            default="entry",
            description="Target type (entry, attr, etc.)",
        )
        dn_pattern: str = Field(
            default="*",
            description="DN pattern for target matching",
        )
        attributes: list[str] = Field(
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
            attributes: list[str] | None = None,
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

    class AclSubject(BaseModel):
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

    class AclPermissions(BaseModel):
        """ACL permissions specification."""

        grant_type: str = Field(
            default="allow",
            description="Grant type: allow or deny",
        )
        granted_permissions: list[str] = Field(
            default_factory=list,
            description="Granted permissions (read, write, etc.)",
        )
        denied_permissions: list[str] = Field(
            default_factory=list,
            description="Denied permissions (read, write, etc.)",
        )

        @model_validator(mode="before")
        @classmethod
        def handle_permissions_parameter(
            cls, data: dict[str, Any] | list[Any] | str
        ) -> dict[str, Any] | list[Any] | str:
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
        def permissions(self) -> list[str]:
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
            permissions: list[str],
            denied_permissions: list[str] | None = None,
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

    class Acl(BaseModel):
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
        ) -> FlextResult[FlextLdapModels.Acl]:
            """Create Acl instance."""
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

    class AclRule(BaseModel):
        """Generic ACL rule structure."""

        id: str | None = Field(default=None, description="Rule identifier")
        target: FlextLdapModels.AclTarget
        subject: FlextLdapModels.AclSubject
        permissions: FlextLdapModels.AclPermissions
        conditions: dict[str, object] = Field(
            default_factory=dict,
            description="Additional conditions",
        )
        enabled: bool = Field(default=True, description="Whether the rule is enabled")

    class AclInfo(BaseModel):
        """ACL information model with format and metadata."""

        format: str = Field(
            default="aci",
            description="ACL format (aci, slapd, etc.)",
        )
        server_type: str = Field(
            default="generic",
            description="LDAP server type this ACL format is for",
        )

    # =========================================================================
    # CONFIG INFO MODELS - Configuration metadata from FlextLdapConfig
    # =========================================================================

    # =========================================================================
    # CONFIG RUNTIME METADATA - Composite model for configuration metadata
    # =========================================================================

    class ConfigRuntimeMetadata(BaseModel):
        """Composite config metadata with nested sections.

        Reduces 5 models to 1 by grouping related config information via nested classes.
        through computed fields.
        """

        class Authentication(BaseModel):
            """Authentication configuration information."""

            bind_dn_configured: bool = Field(..., description="Bind DN is configured")
            bind_password_configured: bool = Field(
                ..., description="Bind password is configured"
            )
            base_dn: str = Field(..., description="LDAP base DN")
            anonymous_bind: bool = Field(..., description="Using anonymous bind")

        class Pooling(BaseModel):
            """Connection pooling configuration information."""

            pool_size: int = Field(..., description="Connection pool size")
            pool_timeout: int = Field(..., description="Pool timeout in seconds")
            pool_utilization: str = Field(..., description="Pool utilization string")

        class OperationLimits(BaseModel):
            """Operation limits configuration information."""

            operation_timeout: int = Field(
                ..., description="Operation timeout in seconds"
            )
            size_limit: int = Field(..., description="Search size limit")
            time_limit: int = Field(..., description="Search time limit in seconds")
            connection_timeout: int = Field(
                ..., description="Connection timeout in seconds"
            )
            total_timeout: int = Field(
                ..., description="Total timeout (operation + connection)"
            )

        class Caching(BaseModel):
            """Caching configuration information."""

            caching_enabled: bool = Field(..., description="Caching is enabled")
            cache_ttl: int = Field(..., description="Cache TTL in seconds")
            cache_ttl_minutes: int = Field(..., description="Cache TTL in minutes")
            cache_effective: bool = Field(
                ..., description="Caching is effectively active"
            )

        class Retry(BaseModel):
            """Retry configuration information."""

            retry_attempts: int = Field(..., description="Number of retry attempts")
            retry_delay: int = Field(
                ..., description="Delay between retries in seconds"
            )
            total_retry_time: int = Field(
                ..., description="Total retry time (attempts × delay)"
            )
            retry_enabled: bool = Field(..., description="Retrying is enabled")

        # Composite sections
        authentication: Authentication = Field(
            ..., description="Authentication configuration metadata"
        )
        pooling: Pooling = Field(..., description="Pooling configuration metadata")
        operation_limits: OperationLimits = Field(
            ..., description="Operation limits configuration metadata"
        )
        caching: Caching = Field(..., description="Caching configuration metadata")
        retry: Retry = Field(..., description="Retry configuration metadata")

    class ConfigCapabilities(BaseModel):
        """Configuration LDAP capabilities information."""

        supports_ssl: bool = Field(..., description="SSL/TLS is supported")
        supports_caching: bool = Field(..., description="Caching is supported")
        supports_retry: bool = Field(..., description="Retry is supported")
        supports_debug: bool = Field(..., description="Debug logging is supported")
        has_authentication: bool = Field(
            ..., description="Authentication is configured"
        )
        has_pooling: bool = Field(..., description="Connection pooling is enabled")
        is_production_ready: bool = Field(
            ..., description="Configuration is production-ready"
        )

    # =========================================================================
    # ACL MODEL CLASSES - Server-specific ACL representations
    # =========================================================================

    class OpenLdapAcl(BaseModel):
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
            # ACL parsing constants
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

                return FlextResult[FlextLdapModels.OpenLdapAcl].ok(
                    cls(
                        access_line=access_line,
                        target_spec=target_spec,
                        subject_spec=subject_spec or "*",
                        permissions=permissions or "read",
                    )
                )
            except Exception as e:
                return FlextResult[FlextLdapModels.OpenLdapAcl].fail(
                    f"Failed to create OpenLdapAcl: {e}"
                )

    class OracleAcl(BaseModel):
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
                return FlextResult[FlextLdapModels.OracleAcl].ok(
                    cls(
                        aci_value=aci_value,
                        target_dn=target_dn,
                        subject_spec=subject_spec or "*",
                        permissions=permissions or "read",
                    )
                )
            except Exception as e:
                return FlextResult[FlextLdapModels.OracleAcl].fail(
                    f"Failed to create OracleAcl: {e}"
                )

    class AciFormat(BaseModel):
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
                return FlextResult[FlextLdapModels.AciFormat].ok(
                    cls(
                        aci_string=aci_string,
                        target=target or "*",
                        subject=subject or "*",
                        permissions=permissions or "read",
                    )
                )
            except Exception as e:
                return FlextResult[FlextLdapModels.AciFormat].fail(
                    f"Failed to create AciFormat: {e}"
                )

    class ConversionResult(BaseModel):
        """Result of ACL/entry conversion operations."""

        success: bool = Field(..., description="Whether conversion succeeded")
        original_format: str = Field(..., description="Original format type")
        target_format: str = Field(..., description="Target format type")
        converted_data: dict[str, object] = Field(
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
            *,
            success: bool,
            original_format: str,
            target_format: str,
            converted_data: dict[str, object] | None = None,
            errors: list[str] | None = None,
            warnings: list[str] | None = None,
        ) -> FlextResult[FlextLdapModels.ConversionResult]:
            """Create ConversionResult from conversion operation."""
            try:
                return FlextResult[FlextLdapModels.ConversionResult].ok(
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
                return FlextResult[FlextLdapModels.ConversionResult].fail(
                    f"Failed to create ConversionResult: {e}"
                )

    class ServerInfo(FlextModels.ArbitraryTypesModel):
        """Model for LDAP server information from Root DSE.

        Uses FlextModels.ArbitraryTypesModel to allow server-specific attributes.
        """

        model_config = ConfigDict(extra="allow")

        naming_contexts: list[str] = Field(
            default_factory=list, description="Naming contexts"
        )
        supported_ldap_version: list[str] = Field(
            default_factory=list, description="Supported LDAP versions"
        )
        supported_sasl_mechanisms: list[str] = Field(
            default_factory=list, description="Supported SASL mechanisms"
        )
        supported_controls: list[str] = Field(
            default_factory=list, description="Supported controls"
        )
        supported_extensions: list[str] = Field(
            default_factory=list, description="Supported extensions"
        )
        vendor_name: str | None = Field(default=None, description="Vendor name")
        vendor_version: str | None = Field(default=None, description="Vendor version")

    class AdditionalAttributes(FlextModels.ArbitraryTypesModel):
        """Model for additional LDAP attributes with dynamic schema support."""

        model_config = ConfigDict(extra="allow")

    class EntryChanges(FlextModels.ArbitraryTypesModel):
        """Model for LDAP entry attribute changes."""

        model_config = ConfigDict(extra="allow")

    class ServerCapabilities(FlextModels.ArbitraryTypesModel):
        """Model for LDAP server capabilities."""

        model_config = ConfigDict(extra="forbid")

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

    class ServerAttributes(FlextModels.ArbitraryTypesModel):
        """Model for server-specific LDAP attributes."""

        model_config = ConfigDict(extra="allow")

    class RootDSE(FlextModels.ArbitraryTypesModel):
        """Model for LDAP Root DSE (DSA-Specific Entry) information."""

        model_config = ConfigDict(extra="forbid")

        naming_contexts: list[str] = Field(
            default_factory=list, description="Naming contexts"
        )
        supported_ldap_version: list[str] = Field(
            default_factory=list, description="Supported LDAP versions"
        )
        supported_sasl_mechanisms: list[str] = Field(
            default_factory=list, description="Supported SASL mechanisms"
        )
        supported_controls: list[str] = Field(
            default_factory=list, description="Supported controls"
        )
        supported_extensions: list[str] = Field(
            default_factory=list, description="Supported extensions"
        )
        subschema_subentry: str | None = Field(
            default=None, description="Subschema subentry DN"
        )
        vendor_name: str | None = Field(default=None, description="Vendor name")
        vendor_version: str | None = Field(default=None, description="Vendor version")

    # =========================================================================
    # REQUEST MODELS - High-level API request objects
    # =========================================================================

    # =========================================================================
    # PYDANTIC 2.11 DISCRIMINATED UNION - Polymorphic LDAP Entry Types
    # =========================================================================
    #
    # AnyLdapEntry enables automatic routing and type narrowing for polymorphic
    # LDAP operations. Pydantic 2.11 uses the 'entry_type' field to automatically
    # select the correct subclass during deserialization and validation.
    #
    # Usage Examples:
    #
    #   from typing import Annotated, Union
    #   from pydantic import TypeAdapter
    #
    #   # Automatic type routing in API responses
    #   entries = TypeAdapter(list[AnyLdapEntry]).validate_python(json_data)
    #   for entry in entries:
    #       match entry.entry_type:
    #           case "user":
    #               process_user(entry)
    #           case "group":
    #               process_group(entry)
    #           case _:
    #               process_generic_entry(entry)
    #
    #   # Polymorphic LDAP search results
    #   search_results: list[AnyLdapEntry] = api.search_polymorphic(query)
    #
    # Benefits:
    # - Automatic type routing without manual type checking
    # - Type-safe pattern matching (match/case in Python 3.10+)
    # - Cleaner, more maintainable code
    # - Full Pydantic 2.11 validation support
    # - Zero runtime type checking overhead


__all__ = [
    "AnyLdapEntry",
    "FlextLdapModels",
]

# ============================================================================
# PYDANTIC 2.11 DISCRIMINATED UNION - Automatic polymorphic routing
# ============================================================================
#
# Enables type-safe polymorphic handling of LDAP entries with automatic
# routing based on the 'entry_type' discriminator field.
#
# This is the killer feature that makes polymorphic deserialization work
# automatically without manual type checking or Factory methods.

AnyLdapEntry = Annotated[
    FlextLdapModels.Entry,
    Discriminator("entry_type"),
]

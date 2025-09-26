"""Unified LDAP models for flext-ldap - ALL models consolidated into FlextLdapModels.

This module consolidates ALL LDAP models, entities, and value objects into a single
FlextLdapModels class following FLEXT one-class-per-module standards.

Eliminates previous triple model system (models.py + entities.py + value_objects.py).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Final, cast, override

from pydantic import Field, SecretStr, ValidationInfo, field_validator

from flext_core import FlextConstants, FlextModels, FlextResult
from flext_ldap.constants import FlextLdapConstants
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

    NO legacy compatibility maintained - clean consolidated implementation only.
    """

    # =========================================================================
    # VALUE OBJECTS - Immutable LDAP value objects
    # =========================================================================

    class DistinguishedName(FlextModels.Value):
        """LDAP Distinguished Name value object with RFC 2253 compliance.

        Extends FlextModels.Value for proper Pydantic 2 validation and composition.
        """

        value: str = Field(..., min_length=1, description="Distinguished Name string")

        @field_validator("value")
        @classmethod
        def validate_dn_format(cls, v: str) -> str:
            """Validate Distinguished Name format and content."""
            if not v or not v.strip():
                msg = "Distinguished Name cannot be empty"
                raise ValueError(msg)
            # Basic DN validation - full RFC 2253 validation would be more complex
            if "=" not in v:
                msg = "Invalid DN format - missing attribute=value pairs"
                raise ValueError(msg)
            return v.strip()

        @property
        def rdn(self) -> str:
            """Get the Relative Distinguished Name (first component)."""
            return self.value.split(",")[0].strip()

        @classmethod
        def create(
            cls,
            dn_string: str,
        ) -> FlextResult[FlextLdapModels.DistinguishedName]:
            """Create DN with validation."""
            try:
                dn_obj = cls(value=dn_string.strip())
                return FlextResult[FlextLdapModels.DistinguishedName].ok(dn_obj)
            except ValueError as e:
                return FlextResult[FlextLdapModels.DistinguishedName].fail(str(e))

    class Filter(FlextModels.Value):
        """LDAP filter value object with RFC 4515 compliance.

        Extends FlextModels.Value for proper Pydantic 2 validation and composition.
        """

        expression: str = Field(..., min_length=1, description="LDAP filter expression")

        @field_validator("expression")
        @classmethod
        def validate_filter_syntax(cls, v: str) -> str:
            """Validate LDAP filter syntax and format."""
            if not v or not v.strip():
                msg = "LDAP filter cannot be empty"
                raise ValueError(msg)
            # Basic filter validation
            if not (v.startswith("(") and v.endswith(")")):
                msg = "LDAP filter must be enclosed in parentheses"
                raise ValueError(msg)
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

        BASE: Final[str] = "base"
        ONELEVEL: Final[str] = "onelevel"
        SUBTREE: Final[str] = "subtree"

        @field_validator("value")
        @classmethod
        def validate_scope_value(cls, v: str) -> str:
            """Validate LDAP search scope value."""
            valid_scopes = {cls.BASE, cls.ONELEVEL, cls.SUBTREE}
            if v not in valid_scopes:
                msg = f"Invalid scope: {v}. Must be one of {valid_scopes}"
                raise ValueError(msg)
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
            default=False, description="No user modification"
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
            default_factory=list, description="Superior classes"
        )
        must: list[str] = Field(default_factory=list, description="Required attributes")
        may: list[str] = Field(default_factory=list, description="Optional attributes")
        kind: str = Field(default="STRUCTURAL", description="Object class kind")
        is_obsolete: bool = Field(default=False, description="Obsolete flag")

    @dataclass(frozen=True)
    class ServerQuirks:
        """LDAP server-specific quirks and behaviors."""

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
        attribute_name_mappings: dict[str, str] = field(default_factory=dict)
        object_class_mappings: dict[str, str] = field(default_factory=dict)
        dn_format_preferences: list[str] = field(default_factory=list)
        search_scope_limitations: set[str] = field(default_factory=set)
        filter_syntax_quirks: list[str] = field(default_factory=list)
        modify_operation_quirks: list[str] = field(default_factory=list)

    @dataclass(frozen=True)
    class SchemaDiscoveryResult:
        """Result of LDAP schema discovery operation."""

        server_info: dict[str, object]
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

    class FlextLdapBaseModel(FlextModels.ArbitraryTypesModel):
        """Base model class with common LDAP entity configuration and validation.

        Uses ArbitraryTypesModel instead of TimestampedModel to avoid timestamp conflicts.
        Provides LDAP-specific configuration for all entity models.
        """

        # LDAP-specific timestamp fields (nullable)
        created_at: datetime | None = Field(
            default=None, description="Creation timestamp"
        )
        updated_at: datetime | None = Field(
            default=None, description="Last update timestamp"
        )

    class FlextLdapValidationMixin:
        """Mixin providing common field validation methods for LDAP entities.

        Centralizes validation logic to eliminate duplication across model classes.
        """

        @staticmethod
        def validate_dn_field(v: str) -> str:
            """Common DN validation using centralized validation."""
            validation_result: FlextResult[None] = FlextLdapValidations.validate_dn(
                v
            ).map(lambda _: None)
            if validation_result.is_failure:
                raise ValueError(validation_result.error)
            return v.strip()

        @staticmethod
        def validate_email_field(value: str | None) -> str | None:
            """Common email validation using centralized validation."""
            validation_result: FlextResult[None] = FlextLdapValidations.validate_email(
                str(value) if value is not None else ""
            ).map(lambda _: None)
            if validation_result.is_failure:
                raise ValueError(validation_result.error)
            return value

        @staticmethod
        def validate_password_field(value: str | None) -> str | None:
            """Common password validation using centralized validation."""
            validation_result: FlextResult[None] = (
                FlextLdapValidations.validate_password(
                    str(value) if value is not None else ""
                ).map(lambda _: None)
            )
            if validation_result.is_failure:
                raise ValueError(validation_result.error)
            return value

        @staticmethod
        def validate_required_string_field(v: str) -> str:
            """Common validation for required string fields."""
            if not v or not v.strip():
                msg = "Required field cannot be empty"
                raise ValueError(msg)
            return v.strip()

    class FlextLdapEntityBase(FlextLdapBaseModel, FlextLdapValidationMixin):
        """Base class for LDAP entities with common fields and validation.

        Provides common fields and validation methods that are shared
        across multiple LDAP entity types.
        """

        # Timestamp fields inherited from FlextLdapBaseModel

        # Common additional attributes field
        additional_attributes: dict[
            str, FlextLdapTypes.LdapEntries.EntryAttributeValue
        ] = Field(
            default_factory=dict,
            description="Additional LDAP attributes",
        )

    # =========================================================================
    # CORE LDAP ENTITIES - Primary Domain Objects
    # =========================================================================

    class LdapUser(FlextLdapEntityBase):
        """LDAP User entity with enterprise attributes.

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
        uid: str | None = Field(None, description="User ID")
        sn: str | None = Field(None, description="Surname")
        given_name: str | None = Field(None, description="Given Name")

        # Contact information
        mail: str | None = Field(None, description="Primary email address")
        telephone_number: str | None = Field(None, description="Primary phone number")
        mobile: str | None = Field(None, description="Mobile phone number")

        # Organizational
        department: str | None = Field(None, description="Department")
        title: str | None = Field(None, description="Job title")
        organization: str | None = Field(None, description="Organization")
        organizational_unit: str | None = Field(None, description="Organizational Unit")

        # Authentication
        user_password: SecretStr | None = Field(None, description="User password")

        # LDAP metadata
        object_classes: list[str] = Field(
            default_factory=lambda: ["person", "organizationalPerson", "inetOrgPerson"],
            description="LDAP object classes",
        )

        # Legacy compatibility fields
        id: str = Field(default="", description="Legacy ID field")
        attributes: FlextLdapTypes.LdapEntries.EntryAttributeDict = Field(
            default_factory=dict,
            description="Legacy attributes dict",
        )
        status: str | None = Field(default=None, description="User status")
        created_at: datetime | None = Field(
            default=None, description="Creation timestamp"
        )
        display_name: str | None = Field(default=None, description="Display Name")
        modified_at: str | None = Field(
            default=None,
            description="Last modification timestamp (legacy field)",
        )
        # Test compatibility fields
        created_timestamp: datetime | None = Field(
            default=None, description="Creation timestamp (test compatibility)"
        )
        modified_timestamp: datetime | None = Field(
            default=None, description="Modification timestamp (test compatibility)"
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format using centralized validation."""
            return cls.validate_dn_field(v)

        @field_validator("mail")
        @classmethod
        def validate_email(cls, value: str | None) -> str | None:
            """Validate email format using centralized validation."""
            return cls.validate_email_field(value)

        @field_validator("cn")
        @classmethod
        def validate_cn(cls, v: str) -> str:
            """Validate Common Name."""
            return cls.validate_required_string_field(v)

        @field_validator("object_classes")
        @classmethod
        def validate_object_classes(cls, v: list[str]) -> list[str]:
            """Validate object classes."""
            if not v:
                msg = "At least one object class is required"
                raise ValueError(msg)
            return v

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate user business rules with enhanced error handling."""
            try:
                # User-specific validations
                if "person" not in self.object_classes:
                    return FlextResult[None].fail(
                        "User must have 'person' object class"
                    )

                if not self.cn:
                    return FlextResult[None].fail("User must have a Common Name")

                return FlextResult[None].ok(None)
            except Exception as e:
                return FlextResult[None].fail(f"Business rule validation failed: {e}")

        def to_ldap_attributes(self) -> dict[str, list[str]]:
            """Convert user to LDAP attributes format."""
            attributes: dict[str, list[str]] = {}

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
            cls, ldap_attributes: dict[str, list[str]]
        ) -> FlextResult[FlextLdapModels.LdapUser]:
            """Create user from LDAP attributes."""
            try:
                # Extract DN
                dn_values = ldap_attributes.get("dn", [])
                if not dn_values:
                    return FlextResult[FlextLdapModels.LdapUser].fail("DN is required")
                dn = dn_values[0]

                # Extract core attributes
                cn_values = ldap_attributes.get("cn", [])
                cn = cn_values[0] if cn_values else ""

                uid_values = ldap_attributes.get("uid", [])
                uid = uid_values[0] if uid_values else None

                sn_values = ldap_attributes.get("sn", [])
                sn = sn_values[0] if sn_values else None

                given_name_values = ldap_attributes.get("givenName", [])
                given_name = given_name_values[0] if given_name_values else None

                mail_values = ldap_attributes.get("mail", [])
                mail = mail_values[0] if mail_values else None

                telephone_number_values = ldap_attributes.get("telephoneNumber", [])
                telephone_number = (
                    telephone_number_values[0] if telephone_number_values else None
                )

                mobile_values = ldap_attributes.get("mobile", [])
                mobile = mobile_values[0] if mobile_values else None

                department_values = ldap_attributes.get("department", [])
                department = department_values[0] if department_values else None

                title_values = ldap_attributes.get("title", [])
                title = title_values[0] if title_values else None

                organization_values = ldap_attributes.get("o", [])
                organization = organization_values[0] if organization_values else None

                organizational_unit_values = ldap_attributes.get("ou", [])
                organizational_unit = (
                    organizational_unit_values[0]
                    if organizational_unit_values
                    else None
                )

                object_classes = ldap_attributes.get(
                    "objectClass", ["person", "organizationalPerson", "inetOrgPerson"]
                )

                # Create user
                user = cls(
                    dn=dn,
                    cn=cn,
                    uid=uid,
                    sn=sn,
                    given_name=given_name,
                    mail=mail,
                    telephone_number=telephone_number,
                    mobile=mobile,
                    department=department,
                    title=title,
                    organization=organization,
                    organizational_unit=organizational_unit,
                    object_classes=object_classes,
                    user_password=None,  # Never store passwords from LDAP
                    additional_attributes={},
                    id="",
                    attributes={},
                    status="active",
                    created_at=None,
                    display_name=cn,
                    modified_at=None,
                    created_timestamp=None,
                    modified_timestamp=None,
                )

                return FlextResult[FlextLdapModels.LdapUser].ok(user)
            except Exception as e:
                return FlextResult[FlextLdapModels.LdapUser].fail(
                    f"Failed to create user from LDAP attributes: {e}"
                )

        def get_attribute(
            self,
            name: str,
        ) -> FlextLdapTypes.LdapEntries.EntryAttributeValue | None:
            """Get attribute value by name with enhanced error handling."""
            try:
                return self.additional_attributes.get(name)
            except Exception:
                return None

        def set_attribute(
            self,
            name: str,
            value: FlextLdapTypes.LdapEntries.EntryAttributeValue,
        ) -> None:
            """Set attribute value by name with enhanced error handling."""
            try:
                self.additional_attributes[name] = value
            except Exception as e:
                msg = f"Failed to set attribute {name}: {e}"
                raise ValueError(msg) from e

        def get_rdn(self) -> str:
            """Extract Relative Distinguished Name (first component) with enhanced error handling."""
            try:
                return self.dn.split(",")[0] if "," in self.dn else self.dn
            except Exception:
                return self.dn

        def get_parent_dn(self) -> str | None:
            """Extract parent DN with enhanced error handling."""
            try:
                parts = self.dn.split(",", 1)
                return parts[1] if len(parts) > 1 else None
            except Exception:
                return None

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
                sn = kwargs.get("sn")
                given_name = kwargs.get("given_name")
                mail = kwargs.get("mail")
                telephone_number = kwargs.get("telephone_number")
                mobile = kwargs.get("mobile")
                department = kwargs.get("department")
                title = kwargs.get("title")
                organization = kwargs.get("organization")
                organizational_unit = kwargs.get("organizational_unit")
                user_password_raw = kwargs.get("user_password")

                # Create user_password SecretStr if provided
                user_password = None
                if user_password_raw and isinstance(user_password_raw, str):
                    user_password = SecretStr(user_password_raw)

                # Create user with explicit arguments to avoid **kwargs typing issues
                user = cls(
                    dn=dn,
                    cn=cn,
                    uid=uid,
                    sn=cast("str | None", sn) if sn is not None else None,
                    given_name=cast("str | None", given_name)
                    if given_name is not None
                    else None,
                    mail=cast("str | None", mail) if mail is not None else None,
                    telephone_number=cast("str | None", telephone_number)
                    if telephone_number is not None
                    else None,
                    mobile=cast("str | None", mobile) if mobile is not None else None,
                    department=cast("str | None", department)
                    if department is not None
                    else None,
                    title=cast("str | None", title) if title is not None else None,
                    organization=cast("str | None", organization)
                    if organization is not None
                    else None,
                    organizational_unit=cast("str | None", organizational_unit)
                    if organizational_unit is not None
                    else None,
                    user_password=user_password,
                    # Use defaults for other fields
                    object_classes=["person", "organizationalPerson", "inetOrgPerson"],
                    id="",
                    attributes={},
                    status="active",
                    display_name=cn,  # Use cn as display name by default
                )
                return FlextResult[FlextLdapModels.LdapUser].ok(user)
            except Exception as e:
                return FlextResult[FlextLdapModels.LdapUser].fail(
                    f"User creation failed: {e}"
                )

    class Group(FlextLdapEntityBase):
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
        gid_number: int | None = Field(None, description="Group ID Number")

        # Group membership
        member_dns: list[str] = Field(
            default_factory=list,
            description="Member Distinguished Names",
        )
        unique_member_dns: list[str] = Field(
            default_factory=list,
            description="Unique Member Distinguished Names",
        )

        # Legacy compatibility
        id: str = Field(default="", description="Legacy ID field")
        members: list[str] = Field(
            default_factory=list,
            description="Legacy members list",
        )
        attributes: FlextLdapTypes.LdapEntries.EntryAttributeDict = Field(
            default_factory=dict,
            description="Legacy attributes dict",
        )
        status: str | None = Field(default=None, description="Group status")
        modified_at: str | None = Field(
            default=None,
            description="Last modification timestamp (legacy field)",
        )
        # Test compatibility fields
        created_timestamp: datetime | None = Field(
            default=None, description="Creation timestamp (test compatibility)"
        )
        modified_timestamp: datetime | None = Field(
            default=None, description="Modification timestamp (test compatibility)"
        )

        # Metadata
        description: str | None = Field(None, description="Group description")
        object_classes: list[str] = Field(
            default_factory=lambda: ["groupOfNames", "top"],
            description="LDAP object classes",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format using centralized validation."""
            return cls.validate_dn_field(v)

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate group business rules with enhanced error handling."""
            try:
                # Group-specific validations
                if "groupOfNames" not in self.object_classes:
                    return FlextResult[None].fail(
                        "Group must have 'groupOfNames' object class",
                    )

                return FlextResult[None].ok(None)
            except Exception as e:
                return FlextResult[None].fail(f"Business rule validation failed: {e}")

        @property
        def member(self) -> list[str]:
            """Legacy member property - returns member_dns for backward compatibility."""
            return self.member_dns

        @member.setter
        def member(self, value: list[str]) -> None:
            """Set member_dns from legacy member property."""
            self.member_dns = value

        def to_ldap_attributes(self) -> dict[str, list[str]]:
            """Convert group to LDAP attributes format."""
            attributes: dict[str, list[str]] = {}

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
            cls, ldap_attributes: dict[str, list[str]]
        ) -> FlextResult[FlextLdapModels.Group]:
            """Create group from LDAP attributes."""
            try:
                # Extract DN
                dn_values = ldap_attributes.get("dn", [])
                if not dn_values:
                    return FlextResult[FlextLdapModels.Group].fail("DN is required")
                dn = dn_values[0]

                # Extract core attributes
                cn_values = ldap_attributes.get("cn", [])
                cn = cn_values[0] if cn_values else ""

                gid_number_values = ldap_attributes.get("gidNumber", [])
                gid_number = int(gid_number_values[0]) if gid_number_values else None

                description_values = ldap_attributes.get("description", [])
                description = description_values[0] if description_values else None

                object_classes = ldap_attributes.get(
                    "objectClass", ["groupOfNames", "top"]
                )

                member_dns = ldap_attributes.get("member", [])
                unique_member_dns = ldap_attributes.get("uniqueMember", [])

                # Create group
                group = cls(
                    dn=dn,
                    cn=cn,
                    gid_number=gid_number,
                    description=description,
                    member_dns=member_dns,
                    unique_member_dns=unique_member_dns,
                    members=member_dns,  # Legacy compatibility
                    object_classes=object_classes,
                    id="",
                    attributes={},
                    status="active",
                    additional_attributes={},
                    created_timestamp=None,
                    modified_timestamp=None,
                )

                return FlextResult[FlextLdapModels.Group].ok(group)
            except Exception as e:
                return FlextResult[FlextLdapModels.Group].fail(
                    f"Failed to create group from LDAP attributes: {e}"
                )

        def has_member(self, member_dn: str) -> bool:
            """Check if DN is a member of this group with enhanced error handling."""
            try:
                return (
                    member_dn in self.member_dns
                    or member_dn in self.unique_member_dns
                    or member_dn in self.members
                )
            except Exception:
                return False

        def add_member(self, member_dn: str) -> FlextResult[None]:
            """Add member to group with enhanced error handling."""
            try:
                if member_dn not in self.member_dns:
                    self.member_dns.append(member_dn)
                if member_dn not in self.members:
                    self.members.append(member_dn)
                return FlextResult[None].ok(None)
            except Exception as e:
                return FlextResult[None].fail(f"Failed to add member: {e}")

        def remove_member(self, member_dn: str) -> FlextResult[None]:
            """Remove member from group with enhanced error handling."""
            try:
                if member_dn in self.member_dns:
                    self.member_dns.remove(member_dn)
                if member_dn in self.members:
                    self.members.remove(member_dn)
                    return FlextResult[None].ok(None)
                return FlextResult[None].fail(f"Member {member_dn} not found in group")
            except Exception as e:
                return FlextResult[None].fail(f"Failed to remove member: {e}")

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
            try:
                # Create group with explicit arguments to avoid **kwargs typing issues
                group = cls(
                    dn=dn,
                    cn=cn,
                    gid_number=gid_number,
                    description=description,
                    # Use defaults for other fields
                    member_dns=[],
                    unique_member_dns=[],
                    id="",
                    members=[],
                    attributes={},
                    status="active",
                    object_classes=["groupOfNames", "top"],
                )
                return FlextResult[FlextLdapModels.Group].ok(group)
            except Exception as e:
                return FlextResult[FlextLdapModels.Group].fail(
                    f"Group creation failed: {e}"
                )

    class Entry(FlextLdapEntityBase):
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
        object_classes: list[str] = Field(
            default_factory=list,
            description="LDAP object classes",
        )

        # Test compatibility fields
        created_timestamp: datetime | None = Field(
            default=None, description="Creation timestamp (test compatibility)"
        )
        modified_timestamp: datetime | None = Field(
            default=None, description="Modification timestamp (test compatibility)"
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format using centralized validation."""
            return cls.validate_dn_field(v)

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
            try:
                attribute_value = self.attributes.get(name)
                if attribute_value is None:
                    return None

                # Convert different types to string list for consistent access
                if isinstance(attribute_value, str):
                    return [attribute_value]
                if isinstance(attribute_value, bytes):
                    return [attribute_value.decode("utf-8")]
                if isinstance(attribute_value, list):
                    # Convert all items to strings
                    return [
                        item.decode("utf-8") if isinstance(item, bytes) else str(item)
                        for item in attribute_value
                    ]
                # This should never happen given our type definition, but mypy needs it
                return [str(attribute_value)]
            except Exception:
                return None

        def set_attribute(
            self,
            name: str,
            value: FlextLdapTypes.LdapEntries.EntryAttributeValue,
        ) -> None:
            """Set attribute value by name with enhanced error handling."""
            try:
                self.attributes[name] = value
            except Exception as e:
                msg = f"Failed to set attribute {name}: {e}"
                raise ValueError(msg) from e

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists with enhanced error handling."""
            try:
                return name in self.attributes
            except Exception:
                return False

        def get_rdn(self) -> str:
            """Extract Relative Distinguished Name with enhanced error handling."""
            try:
                return self.dn.split(",")[0] if "," in self.dn else self.dn
            except Exception:
                return self.dn

    # =========================================================================
    # LDAP OPERATION ENTITIES - Request/Response Objects
    # =========================================================================

    class SearchRequest(FlextLdapBaseModel, FlextLdapValidationMixin):
        """LDAP Search Request entity with comprehensive parameters."""

        # Search scope
        base_dn: str = Field(..., description="Search base Distinguished Name")
        filter_str: str = Field(..., description="LDAP search filter")
        scope: str = Field(
            default="subtree",
            description="Search scope: base, onelevel, subtree",
            pattern="^(base|onelevel|subtree|BASE|ONELEVEL|SUBTREE)$",
        )

        # Attribute selection
        attributes: list[str] | None = Field(
            default=None,
            description="Attributes to return (None = all)",
        )

        # Search limits - using centralized constants
        size_limit: int = Field(
            default=FlextLdapConstants.Connection.MAX_SIZE_LIMIT,
            description="Maximum number of entries to return",
            ge=0,
        )
        time_limit: int = Field(
            default=FlextConstants.Network.DEFAULT_TIMEOUT,
            description="Search timeout in seconds",
            ge=0,
        )

        # Paging - REQUIRED fields for proper LDAP operations
        page_size: int = Field(
            ...,
            description="Page size for paged results",
            ge=1,
        )
        paged_cookie: bytes | None = Field(
            None,
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
                v
            ).map(lambda _: None)
            if validation_result.is_failure:
                raise ValueError(validation_result.error)
            return v.strip()

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

    class SearchResponse(FlextLdapBaseModel):
        """LDAP Search Response entity."""

        # Results
        entries: list[dict[str, object]] = Field(
            default_factory=list,
            description="Search result entries",
        )

        # Result metadata
        total_count: int = Field(0, description="Total number of entries")
        has_more: bool = Field(default=False, description="More results available")

        # Legacy compatibility
        result_code: int = Field(0, description="LDAP result code")
        result_description: str = Field("", description="Result description")
        matched_dn: str = Field("", description="Matched DN")
        has_more_pages: bool = Field(default=False, description="More pages available")
        next_cookie: bytes | None = Field(None, description="Next page cookie")
        entries_returned: int = Field(0, description="Number of entries returned")
        time_elapsed: float = Field(0.0, description="Search time in seconds")

        @field_validator("entries_returned", mode="before")
        @classmethod
        def set_entries_returned(cls, v: int, info: ValidationInfo) -> int:
            """Auto-calculate entries returned from entries list."""
            if info.data and "entries" in info.data:
                entries = info.data["entries"]
                if isinstance(entries, list):
                    # Type-safe length calculation
                    return len(entries)
                return 0
            return v

    class CreateUserRequest(FlextLdapBaseModel, FlextLdapValidationMixin):
        """LDAP User Creation Request entity."""

        # Required fields
        dn: str = Field(..., description="Distinguished Name for new user")
        uid: str = Field(..., description="User ID")
        cn: str = Field(..., description="Common Name")
        sn: str = Field(..., description="Surname")

        # Required user attributes - making them required for proper user creation
        given_name: str = Field(..., description="Given Name")
        mail: str = Field(..., description="Email address")
        user_password: str = Field(..., description="User password")
        telephone_number: str = Field(..., description="Phone number")
        description: str = Field(..., description="User description")

        # Required organizational fields
        department: str = Field(..., description="Department")
        title: str = Field(..., description="Job title")
        organization: str = Field(..., description="Organization")

        # LDAP metadata
        object_classes: list[str] = Field(
            default_factory=lambda: [
                FlextLdapConstants.ObjectClasses.TOP,
                FlextLdapConstants.ObjectClasses.PERSON,
                FlextLdapConstants.ObjectClasses.INET_ORG_PERSON,
            ],
            description="LDAP object classes",
        )

        # Additional attributes
        additional_attributes: dict[
            str, FlextLdapTypes.LdapEntries.EntryAttributeValue
        ] = Field(
            default_factory=dict,
            description="Additional user attributes",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format using centralized validation."""
            return cls.validate_dn_field(v)

        @field_validator("mail")
        @classmethod
        def validate_email(cls, value: str | None) -> str | None:
            """Validate email format using centralized validation."""
            return cls.validate_email_field(value)

        @field_validator("user_password")
        @classmethod
        def validate_password(cls, value: str | None) -> str | None:
            """Validate password requirements using centralized validation."""
            return cls.validate_password_field(value)

        @field_validator(
            "uid",
            "cn",
            "sn",
            "given_name",
            "mail",
            "user_password",
            "telephone_number",
            "description",
            "department",
            "title",
            "organization",
        )
        @classmethod
        def validate_required_string(cls, v: str) -> str:
            """Validate required string fields."""
            return cls.validate_required_string_field(v)

        def validate_business_rules(self) -> FlextResult[None]:
            """Validate create user request business rules."""
            if not self.dn:
                return FlextResult[None].fail("DN cannot be empty")
            if not self.uid:
                return FlextResult[None].fail("UID cannot be empty")
            if not self.cn:
                return FlextResult[None].fail("Common Name cannot be empty")
            if not self.given_name:
                return FlextResult[None].fail("Given Name cannot be empty")
            if not self.mail:
                return FlextResult[None].fail("Email cannot be empty")
            if not self.user_password:
                return FlextResult[None].fail("Password cannot be empty")
            return FlextResult[None].ok(None)

        def to_user_entity(self) -> FlextLdapModels.LdapUser:
            """Convert request to user entity."""
            return FlextLdapModels.LdapUser(
                id=f"user_{self.uid}",
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
                organizational_unit=None,
                user_password=SecretStr(self.user_password)
                if self.user_password
                else None,
                object_classes=self.object_classes,
                additional_attributes=self.additional_attributes,
                created_at=None,
                modified_at=None,
            )

    class CreateGroupRequest(FlextLdapBaseModel, FlextLdapValidationMixin):
        """LDAP Group Creation Request entity."""

        # Required fields
        dn: str = Field(..., description="Distinguished Name for new group")
        cn: str = Field(..., description="Common Name")

        # Required group attributes
        description: str = Field(..., description="Group description")
        members: list[str] = Field(..., description="Initial group members")

        # LDAP metadata
        object_classes: list[str] = Field(
            default_factory=lambda: ["groupOfNames", "top"],
            description="LDAP object classes",
        )

        @field_validator("dn")
        @classmethod
        def validate_dn(cls, v: str) -> str:
            """Validate Distinguished Name format using centralized validation."""
            return cls.validate_dn_field(v)

        @field_validator("cn", "description")
        @classmethod
        def validate_cn(cls, v: str) -> str:
            """Validate Common Name and description."""
            return cls.validate_required_string_field(v)

        @field_validator("members")
        @classmethod
        def validate_members(cls, v: list[str]) -> list[str]:
            """Validate members list."""
            if not v:
                error_msg = "Members list cannot be empty"
                raise ValueError(error_msg)
            return v

    # =========================================================================
    # CONNECTION AND CONFIGURATION ENTITIES
    # =========================================================================

    class ConnectionInfo(FlextLdapBaseModel, FlextLdapValidationMixin):
        """LDAP Connection Information entity."""

        # Connection details
        server: str = Field(..., description="LDAP server hostname/IP")
        port: int = Field(
            FlextLdapConstants.Protocol.DEFAULT_PORT,
            description="LDAP server port",
            ge=1,
            le=FlextLdapConstants.Protocol.MAX_PORT,
        )
        use_ssl: bool = Field(default=False, description="Use SSL/TLS encryption")
        use_tls: bool = Field(default=False, description="Use StartTLS")

        # Authentication
        bind_dn: str | None = Field(None, description="Bind Distinguished Name")
        bind_password: SecretStr | None = Field(None, description="Bind password")

        # Connection options - using centralized constants
        timeout: int = Field(
            FlextConstants.Network.DEFAULT_TIMEOUT,
            description="Connection timeout in seconds",
            ge=1,
        )
        pool_size: int = Field(
            FlextLdapConstants.Protocol.DEFAULT_POOL_SIZE,
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
        ca_certs_file: str | None = Field(None, description="CA certificates file path")

        @field_validator("server")
        @classmethod
        def validate_server(cls, v: str) -> str:
            """Validate server hostname/IP."""
            return cls.validate_required_string_field(v)

        @field_validator("port")
        @classmethod
        def validate_port(cls, v: int) -> int:
            """Validate port number."""
            if v <= 0 or v > FlextLdapConstants.Protocol.MAX_PORT:
                msg = (
                    f"Port must be between 1 and {FlextLdapConstants.Protocol.MAX_PORT}"
                )
                raise ValueError(msg)
            return v

    # =========================================================================
    # ERROR AND STATUS ENTITIES
    # =========================================================================

    class LdapError(FlextLdapBaseModel):
        """LDAP Error entity with detailed information."""

        # Error details
        error_code: int = Field(..., description="LDAP error code")
        error_message: str = Field(..., description="Error message")
        matched_dn: str = Field("", description="Matched DN")

        # Context
        operation: str = Field("", description="Operation that failed")
        target_dn: str = Field("", description="Target DN")

        # Additional details
        server_info: dict[str, object] = Field(
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
                raise ValueError(msg)
            return v

    class OperationResult(FlextLdapBaseModel):
        """LDAP Operation Result entity."""

        # Result status
        success: bool = Field(..., description="Operation success status")
        result_code: int = Field(0, description="LDAP result code")
        result_message: str = Field("", description="Result message")

        # Operation details
        operation_type: str = Field("", description="Type of operation")
        target_dn: str = Field("", description="Target DN")

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

        @property
        def is_success(self) -> bool:
            """Alias for success field for backward compatibility."""
            return self.success

        @classmethod
        def success_result(
            cls,
            operation_type: str,
            target_dn: str = "",
            data: dict[str, object] | None = None,
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

    @dataclass(frozen=True)
    class ConnectionConfig:
        """LDAP connection configuration value object."""

        server: str
        port: int = FlextLdapConstants.Protocol.DEFAULT_PORT
        use_ssl: bool = False
        bind_dn: str | None = None
        bind_password: str | None = None
        timeout: int = FlextConstants.Network.DEFAULT_TIMEOUT

        @property
        def server_uri(self) -> str:
            """Get server URI."""
            protocol = "ldaps://" if self.use_ssl else "ldap://"
            return f"{protocol}{self.server}:{self.port}"

        @property
        def password(self) -> str | None:
            """Get bind password."""
            return self.bind_password

        @property
        def base_dn(self) -> str:
            """Get base DN (default empty)."""
            return ""

        @override
        def validate(self) -> FlextResult[None]:
            """Validate connection configuration."""
            try:
                if not self.server or not self.server.strip():
                    return FlextResult[None].fail("Server cannot be empty")
                max_port = 65535
                if self.port <= 0 or self.port > max_port:
                    return FlextResult[None].fail("Invalid port number")
                return FlextResult[None].ok(None)
            except Exception as e:
                return FlextResult[None].fail(f"Validation failed: {e}")

    @dataclass(frozen=True)
    class ModifyConfig:
        """LDAP modify operation configuration value object."""

        dn: str
        changes: dict[str, list[tuple[str, list[str]]]]

        @override
        def validate(self) -> FlextResult[None]:
            """Validate modify configuration."""
            try:
                if not self.dn or not self.dn.strip():
                    return FlextResult[None].fail("DN cannot be empty")
                if not self.changes:
                    return FlextResult[None].fail("Changes cannot be empty")
                return FlextResult[None].ok(None)
            except Exception as e:
                return FlextResult[None].fail(f"Validation failed: {e}")

    @dataclass(frozen=True)
    class AddConfig:
        """LDAP add operation configuration value object."""

        dn: str
        attributes: dict[str, list[str]]

        @override
        def validate(self) -> FlextResult[None]:
            """Validate add configuration."""
            try:
                if not self.dn or not self.dn.strip():
                    return FlextResult[None].fail("DN cannot be empty")
                if not self.attributes:
                    return FlextResult[None].fail("Attributes cannot be empty")
                return FlextResult[None].ok(None)
            except Exception as e:
                return FlextResult[None].fail(f"Validation failed: {e}")

    @dataclass(frozen=True)
    class DeleteConfig:
        """LDAP delete operation configuration value object."""

        dn: str

        @override
        def validate(self) -> FlextResult[None]:
            """Validate delete configuration."""
            try:
                if not self.dn or not self.dn.strip():
                    return FlextResult[None].fail("DN cannot be empty")
                return FlextResult[None].ok(None)
            except Exception as e:
                return FlextResult[None].fail(f"Validation failed: {e}")

    @dataclass(frozen=True)
    class SearchConfig:
        """LDAP search operation configuration value object."""

        base_dn: str
        search_filter: str
        attributes: list[str]

        @override
        def validate(self) -> FlextResult[None]:
            """Validate search configuration."""
            try:
                if not self.base_dn or not self.base_dn.strip():
                    return FlextResult[None].fail("Base DN cannot be empty")
                if not self.search_filter or not self.search_filter.strip():
                    return FlextResult[None].fail("Search filter cannot be empty")
                if not self.attributes:
                    return FlextResult[None].fail("Attributes cannot be empty")
                return FlextResult[None].ok(None)
            except Exception as e:
                return FlextResult[None].fail(f"Validation failed: {e}")

    # =========================================================================
    # ACL MODELS - Access Control List models (consolidated from acl/models.py)
    # =========================================================================

    class AclTarget(FlextLdapBaseModel):
        """ACL target specification - what is being protected."""

        target_type: str = Field(
            ..., description="Type of target (dn, attributes, entry)"
        )
        dn_pattern: str = Field(default="*", description="DN pattern for the target")
        attributes: list[str] = Field(
            default_factory=list, description="Specific attributes targeted"
        )
        filter_expression: str = Field(
            default="", description="LDAP filter for dynamic targeting"
        )
        scope: str = Field(default="subtree", description="Scope: base, one, subtree")

        @classmethod
        def create(
            cls,
            target_type: str,
            dn_pattern: str = "*",
            attributes: list[str] | None = None,
            filter_expression: str = "",
            scope: str = "subtree",
        ) -> FlextResult[FlextLdapModels.AclTarget]:
            """Create ACL target with validation."""
            try:
                instance = cls(
                    target_type=target_type,
                    dn_pattern=dn_pattern,
                    attributes=attributes or [],
                    filter_expression=filter_expression,
                    scope=scope,
                )
                return FlextResult[FlextLdapModels.AclTarget].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdapModels.AclTarget].fail(
                    f"ACL target creation failed: {e}"
                )

    class AclSubject(FlextLdapBaseModel):
        """ACL subject specification - who has access."""

        subject_type: str = Field(
            ..., description="Type of subject (user, group, dn, self)"
        )
        identifier: str = Field(
            default="*", description="Subject identifier (DN, group name, etc.)"
        )
        authentication_level: str = Field(
            default="any", description="Required authentication level"
        )

        @classmethod
        def create(
            cls,
            subject_type: str,
            identifier: str = "*",
            authentication_level: str = "any",
        ) -> FlextResult[FlextLdapModels.AclSubject]:
            """Create ACL subject with validation."""
            try:
                instance = cls(
                    subject_type=subject_type,
                    identifier=identifier,
                    authentication_level=authentication_level,
                )
                return FlextResult[FlextLdapModels.AclSubject].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdapModels.AclSubject].fail(
                    f"ACL subject creation failed: {e}"
                )

    class AclPermissions(FlextLdapBaseModel):
        """ACL permissions specification."""

        permissions: list[str] = Field(
            default_factory=list, description="List of granted permissions"
        )
        denied_permissions: list[str] = Field(
            default_factory=list, description="List of explicitly denied permissions"
        )
        grant_type: str = Field(
            default="allow", description="Grant type: allow or deny"
        )

        @classmethod
        def create(
            cls,
            permissions: list[str] | None = None,
            denied_permissions: list[str] | None = None,
            grant_type: str = "allow",
        ) -> FlextResult[FlextLdapModels.AclPermissions]:
            """Create ACL permissions with validation."""
            try:
                instance = cls(
                    permissions=permissions or [],
                    denied_permissions=denied_permissions or [],
                    grant_type=grant_type,
                )
                return FlextResult[FlextLdapModels.AclPermissions].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdapModels.AclPermissions].fail(
                    f"ACL permissions creation failed: {e}"
                )

    class UnifiedAcl(FlextLdapBaseModel):
        """Unified ACL representation - intermediate format for conversion."""

        name: str = Field(default="", description="ACL rule name")
        target: FlextLdapModels.AclTarget = Field(..., description="ACL target")
        subject: FlextLdapModels.AclSubject = Field(..., description="ACL subject")
        permissions: FlextLdapModels.AclPermissions = Field(
            ..., description="ACL permissions"
        )
        priority: int = Field(default=0, description="ACL evaluation priority")
        conditions: dict[str, object] = Field(
            default_factory=dict, description="Additional conditions (time, IP, etc.)"
        )
        metadata: dict[str, object] = Field(
            default_factory=dict, description="Format-specific metadata"
        )

        @classmethod
        def create(
            cls,
            target: FlextLdapModels.AclTarget,
            subject: FlextLdapModels.AclSubject,
            permissions: FlextLdapModels.AclPermissions,
            name: str = "",
            priority: int = 0,
            conditions: dict[str, object] | None = None,
            metadata: dict[str, object] | None = None,
        ) -> FlextResult[FlextLdapModels.UnifiedAcl]:
            """Create unified ACL with validation."""
            try:
                instance = cls(
                    name=name,
                    target=target,
                    subject=subject,
                    permissions=permissions,
                    priority=priority,
                    conditions=conditions or {},
                    metadata=metadata or {},
                )
                return FlextResult[FlextLdapModels.UnifiedAcl].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdapModels.UnifiedAcl].fail(
                    f"Unified ACL creation failed: {e}"
                )

    class OpenLdapAcl(FlextLdapBaseModel):
        """OpenLDAP ACL format representation."""

        access_line: str = Field(..., description="Complete OpenLDAP access line")
        target_spec: str = Field(default="*", description="Target specification")
        by_clauses: list[dict[str, str]] = Field(
            default_factory=list, description="List of by clauses"
        )

        @classmethod
        def create(
            cls,
            access_line: str,
            target_spec: str = "*",
            by_clauses: list[dict[str, str]] | None = None,
        ) -> FlextResult[FlextLdapModels.OpenLdapAcl]:
            """Create OpenLDAP ACL representation."""
            try:
                instance = cls(
                    access_line=access_line,
                    target_spec=target_spec,
                    by_clauses=by_clauses or [],
                )
                return FlextResult[FlextLdapModels.OpenLdapAcl].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdapModels.OpenLdapAcl].fail(
                    f"OpenLDAP ACL creation failed: {e}"
                )

    class OracleAcl(FlextLdapBaseModel):
        """Oracle Directory ACL format representation."""

        orclaci_value: str = Field(..., description="Oracle orclaci attribute value")
        target_type: str = Field(
            default="entry", description="Target type (entry, attr)"
        )
        attributes: list[str] = Field(
            default_factory=list, description="Targeted attributes"
        )
        subject_spec: str = Field(default="", description="Subject specification")
        permissions: list[str] = Field(
            default_factory=list, description="Permissions list"
        )

        @classmethod
        def create(
            cls,
            orclaci_value: str,
            target_type: str = "entry",
            attributes: list[str] | None = None,
            subject_spec: str = "",
            permissions: list[str] | None = None,
        ) -> FlextResult[FlextLdapModels.OracleAcl]:
            """Create Oracle ACL representation."""
            try:
                instance = cls(
                    orclaci_value=orclaci_value,
                    target_type=target_type,
                    attributes=attributes or [],
                    subject_spec=subject_spec,
                    permissions=permissions or [],
                )
                return FlextResult[FlextLdapModels.OracleAcl].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdapModels.OracleAcl].fail(
                    f"Oracle ACL creation failed: {e}"
                )

    class AciFormat(FlextLdapBaseModel):
        """389 DS/Apache DS ACI format representation."""

        aci_value: str = Field(..., description="Complete ACI string")
        target_dn: str = Field(default="", description="Target DN")
        target_attrs: list[str] = Field(
            default_factory=list, description="Target attributes"
        )
        acl_name: str = Field(default="", description="ACL name")
        grant_type: str = Field(default="allow", description="allow or deny")
        permissions: list[str] = Field(default_factory=list, description="Permissions")
        bind_rules: dict[str, str] = Field(
            default_factory=dict, description="Bind rule specifications"
        )

        @classmethod
        def create(
            cls,
            aci_value: str,
            target_dn: str = "",
            target_attrs: list[str] | None = None,
            acl_name: str = "",
            grant_type: str = "allow",
            permissions: list[str] | None = None,
            bind_rules: dict[str, str] | None = None,
        ) -> FlextResult[FlextLdapModels.AciFormat]:
            """Create ACI format representation."""
            try:
                instance = cls(
                    aci_value=aci_value,
                    target_dn=target_dn,
                    target_attrs=target_attrs or [],
                    acl_name=acl_name,
                    grant_type=grant_type,
                    permissions=permissions or [],
                    bind_rules=bind_rules or {},
                )
                return FlextResult[FlextLdapModels.AciFormat].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdapModels.AciFormat].fail(
                    f"ACI format creation failed: {e}"
                )

    class ConversionResult(FlextLdapBaseModel):
        """Result of ACL conversion with warnings and metadata."""

        converted_acl: str = Field(..., description="Converted ACL string")
        source_format: str = Field(..., description="Source ACL format")
        target_format: str = Field(..., description="Target ACL format")
        warnings: list[str] = Field(
            default_factory=list, description="Conversion warnings"
        )
        metadata: dict[str, object] = Field(
            default_factory=dict, description="Conversion metadata"
        )

        @classmethod
        def create(
            cls,
            converted_acl: str,
            source_format: str,
            target_format: str,
            warnings: list[str] | None = None,
            metadata: dict[str, object] | None = None,
        ) -> FlextResult[FlextLdapModels.ConversionResult]:
            """Create conversion result."""
            try:
                instance = cls(
                    converted_acl=converted_acl,
                    source_format=source_format,
                    target_format=target_format,
                    warnings=warnings or [],
                    metadata=metadata or {},
                )
                return FlextResult[FlextLdapModels.ConversionResult].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdapModels.ConversionResult].fail(
                    f"Conversion result creation failed: {e}"
                )


__all__ = [
    "FlextLdapModels",
]

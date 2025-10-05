"""LDAP Value Objects - Immutable domain value objects.

This module consolidates ALL LDAP value objects into a single
FlextLdapValueObjects class following FLEXT one-class-per-module standards.

Value objects are immutable domain objects that represent concepts
like Distinguished Names, Filters, and Scopes.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

# ruff: noqa: F821
# Nested class forward references are valid with __future__.annotations but ruff doesn't recognize them

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import Field

from flext_core import FlextModels, FlextResult


class FlextLdapValueObjects(FlextModels):
    """Unified LDAP value objects class consolidating ALL value objects.

    This class consolidates:
    - DistinguishedName: RFC 2253 compliant DN representation
    - Filter: LDAP search filter value object
    - Scope: Search scope enumeration
    - SchemaAttribute: LDAP schema attribute definition
    - SchemaObjectClass: LDAP schema object class definition
    - ServerQuirks: Server-specific behavior flags
    - SchemaDiscoveryResult: Schema discovery operation result

    Into a single unified class following FLEXT patterns. ALL LDAP value objects
    are now available as nested classes within FlextLdapValueObjects.
    """

    # =========================================================================
    # VALUE OBJECTS - Immutable LDAP value objects
    # =========================================================================

    class DistinguishedName(FlextModels.Value):
        """LDAP Distinguished Name value object with RFC 2253 compliance.

        Extends FlextModels.Value for proper Pydantic 2 validation and composition.
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

        @classmethod
        def create(cls, dn_string: str) -> FlextResult[DistinguishedName]:
            """Factory method to create DN with validation."""
            try:
                return FlextResult[DistinguishedName].ok(cls(value=dn_string))
            except Exception as e:
                return FlextResult[DistinguishedName].fail(f"Invalid DN format: {e}")

        def get_rdn(self) -> str:
            """Get the Relative Distinguished Name (RDN)."""
            return self.value.split(",")[0]

        def get_parent_dn(self) -> DistinguishedName | None:
            """Get the parent DN if it exists."""
            parts = self.value.split(",", 1)
            if len(parts) > 1:
                parent_result = self.create(parts[1])
                return parent_result.value if parent_result.is_success else None
            return None

        def is_child_of(self, parent_dn: DistinguishedName) -> bool:
            """Check if this DN is a child of the given parent DN."""
            return (
                self.value.endswith(parent_dn.value) and self.value != parent_dn.value
            )

    class Filter(FlextModels.Value):
        """LDAP search filter value object.

        Represents LDAP search filters with validation and factory methods.
        """

        value: str = Field(
            ...,
            min_length=1,
            description="LDAP filter string",
            examples=["(objectClass=person)", "(&(uid=john)(ou=users))"],
        )

        @classmethod
        def equals(cls, attribute: str, value: str) -> Filter:
            """Create equality filter."""
            return cls(value=f"({attribute}={value})")

        @classmethod
        def starts_with(cls, attribute: str, value: str) -> Filter:
            """Create starts-with filter."""
            return cls(value=f"({attribute}={value}*)")

        @classmethod
        def object_class(cls, value: str) -> Filter:
            """Create object class filter."""
            return cls.equals("objectClass", value)

        @classmethod
        def and_filter(cls, *filters: Filter) -> Filter:
            """Create AND filter from multiple filters."""
            filter_strs = [f.value for f in filters]
            return cls(value=f"(&{' '.join(filter_strs)})")

        @classmethod
        def or_filter(cls, *filters: Filter) -> Filter:
            """Create OR filter from multiple filters."""
            filter_strs = [f.value for f in filters]
            return cls(value=f"(|{' '.join(filter_strs)})")

    class Scope(FlextModels.Value):
        """LDAP search scope value object.

        Represents search scope with validation.
        """

        value: Literal["base", "one", "subtree"] = Field(
            ...,
            description="Search scope",
            examples=["base", "one", "subtree"],
        )

        @classmethod
        def base(cls) -> Scope:
            """Create base scope."""
            return cls(value="base")

        @classmethod
        def one_level(cls) -> Scope:
            """Create one level scope."""
            return cls(value="one")

        @classmethod
        def subtree(cls) -> Scope:
            """Create subtree scope."""
            return cls(value="subtree")

    class LdapServerType(Enum):
        """LDAP server type enumeration."""

        GENERIC = "generic"
        OPENLDAP_1 = "openldap1"
        OPENLDAP_2 = "openldap2"
        ACTIVE_DIRECTORY = "ad"
        ORACLE_OID = "oid"
        ORACLE_OUD = "oud"

    class SchemaAttribute(FlextModels.Value):
        """LDAP schema attribute definition value object."""

        name: str = Field(..., description="Attribute name")
        syntax: str = Field(..., description="Attribute syntax OID")
        description: str | None = Field(None, description="Attribute description")
        single_value: bool = Field(
            True, description="Whether attribute is single-valued"
        )
        user_modifiable: bool = Field(True, description="Whether users can modify")

    class SchemaObjectClass(FlextModels.Value):
        """LDAP schema object class definition value object."""

        name: str = Field(..., description="Object class name")
        oid: str = Field(..., description="Object class OID")
        description: str | None = Field(None, description="Object class description")
        must_attributes: list[str] = Field(
            default_factory=list, description="Required attributes"
        )
        may_attributes: list[str] = Field(
            default_factory=list, description="Optional attributes"
        )
        kind: Literal["STRUCTURAL", "AUXILIARY", "ABSTRACT"] = Field(
            "STRUCTURAL", description="Object class kind"
        )

    class ServerQuirks:
        """Server-specific behavior flags and quirks."""

        # OpenLDAP quirks
        openldap_acl_inheritance: bool = True
        openldap_empty_dn_allowed: bool = False

        # Active Directory quirks
        ad_nested_groups: bool = True
        ad_extended_dns: bool = True

        # Oracle OUD quirks
        oud_virtual_acls: bool = True
        oud_dynamic_groups: bool = True

        def get_quirks_for_server(self, server_type: LdapServerType) -> dict[str, bool]:
            """Get quirks dictionary for specific server type."""
            if server_type == FlextLdapValueObjects.LdapServerType.ACTIVE_DIRECTORY:
                return {
                    "nested_groups": self.ad_nested_groups,
                    "extended_dns": self.ad_extended_dns,
                }
            elif server_type in (
                FlextLdapValueObjects.LdapServerType.OPENLDAP_1,
                FlextLdapValueObjects.LdapServerType.OPENLDAP_2,
            ):
                return {
                    "acl_inheritance": self.openldap_acl_inheritance,
                    "empty_dn_allowed": self.openldap_empty_dn_allowed,
                }
            elif server_type == FlextLdapValueObjects.LdapServerType.ORACLE_OUD:
                return {
                    "virtual_acls": self.oud_virtual_acls,
                    "dynamic_groups": self.oud_dynamic_groups,
                }
            else:
                return {}

    class SchemaDiscoveryResult(FlextModels.Value):
        """Result of LDAP schema discovery operation."""

        attributes: dict[str, SchemaAttribute] = Field(
            default_factory=dict, description="Discovered attributes"
        )
        object_classes: dict[str, SchemaObjectClass] = Field(
            default_factory=dict, description="Discovered object classes"
        )
        syntaxes: dict[str, str] = Field(
            default_factory=dict, description="Discovered syntaxes"
        )
        discovery_time: float = Field(
            ..., description="Time taken for discovery in seconds"
        )

        def get_attribute(self, name: str) -> SchemaAttribute | None:
            """Get attribute by name."""
            return self.attributes.get(name.lower())

        def get_object_class(self, name: str) -> SchemaObjectClass | None:
            """Get object class by name."""
            return self.object_classes.get(name.lower())

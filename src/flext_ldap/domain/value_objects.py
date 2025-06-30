"""Core LDAP value objects for shared use across projects."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from flext_ldap.utils.constants import (
    DEFAULT_TIMEOUT_SECONDS,
    TCP_PORT_MAX,
    TCP_PORT_MIN,
)

# Constants for magic values


class MigrationStatus(StrEnum):
    """Migration status enumeration."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    ROLLBACK = "rollback"


class LDAPObjectClass(StrEnum):
    """Standard LDAP object classes."""

    TOP = "top"
    PERSON = "person"
    INET_ORG_PERSON = "inetOrgPerson"
    ORGANIZATIONAL_UNIT = "organizationalUnit"
    ORGANIZATION = "organization"
    DOMAIN = "domain"
    GROUP_OF_NAMES = "groupOfNames"
    GROUP_OF_UNIQUE_NAMES = "groupOfUniqueNames"
    CONTAINER = "container"

    # Oracle-specific (for migration detection)
    ORCL_USER = "orclUser"
    ORCL_GROUP = "orclGroup"
    ORCL_CONTEXT = "orclContext"
    ORCL_CONTAINER = "orclContainer"


class DNComponent(BaseModel):
    """A single DN component (attribute=value)."""

    attribute: str = Field(..., description="Attribute name")
    value: str = Field(..., description="Attribute value")

    @field_validator("attribute")
    @classmethod
    def validate_attribute(cls, v: str) -> str:
        """Validate attribute name format."""
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9-]*$", v):
            msg = f"Invalid attribute name: {v}"
            raise ValueError(msg)
        return v.lower()

    @field_validator("value")
    @classmethod
    def validate_value(cls, v: str) -> str:
        """Validate value is not empty."""
        if not v.strip():
            msg = "DN component value cannot be empty"
            raise ValueError(msg)
        return v.strip()

    def __str__(self) -> str:
        """Return string representation."""
        # Escape special characters in value
        escaped_value = self.value.replace("\\", "\\\\").replace(",", "\\,")
        return f"{self.attribute}={escaped_value}"


class LdapDn(BaseModel):
    """LDAP Distinguished Name value object.

    Provides validation, normalization, and manipulation of LDAP DNs.
    """

    components: list[DNComponent] = Field(..., description="DN components")

    @classmethod
    def from_string(cls, dn_string: str) -> LdapDn:
        """Create LdapDn from string representation."""
        if not dn_string.strip():
            msg = "DN cannot be empty"
            raise ValueError(msg)

        components: list[DNComponent] = []
        # Simple DN parsing (would need more sophisticated parsing for complex cases)
        parts = [part.strip() for part in dn_string.split(",")]

        for part in parts:
            if "=" not in part:
                msg = f"Invalid DN component: {part}"
                raise ValueError(msg)

            attr, value = part.split("=", 1)
            components.append(DNComponent(attribute=attr.strip(), value=value.strip()))

        return cls(components=components)

    @field_validator("components")
    @classmethod
    def validate_components(cls, v: list[DNComponent]) -> list[DNComponent]:
        """Validate DN has at least one component."""
        if not v:
            msg = "DN must have at least one component"
            raise ValueError(msg)
        return v

    def __str__(self) -> str:
        """Return string representation of DN."""
        return ",".join(str(component) for component in self.components)

    def normalize(self) -> LdapDn:
        """Return normalized version of DN."""
        # Normalize each component
        normalized_components = [
            DNComponent(
                attribute=component.attribute.lower(),
                value=component.value.strip(),
            )
            for component in self.components
        ]

        return LdapDn(components=normalized_components)

    def get_rdn(self) -> DNComponent:
        """Get the Relative DN (first component)."""
        return self.components[0]

    def get_parent_dn(self) -> LdapDn | None:
        """Get parent DN (all components except first)."""
        if len(self.components) <= 1:
            return None

        return LdapDn(components=self.components[1:])

    def is_child_of(self, potential_parent: LdapDn) -> bool:
        """Check if this DN is a child of the potential parent."""
        if len(self.components) <= len(potential_parent.components):
            return False

        parent_components = self.components[
            len(self.components) - len(potential_parent.components) :
        ]

        for i, component in enumerate(potential_parent.components):
            if (
                component.attribute.lower() != parent_components[i].attribute.lower()
                or component.value.lower() != parent_components[i].value.lower()
            ):
                return False

        return True

    def append_component(self, attribute: str, value: str) -> LdapDn:
        """Append a component to the beginning of the DN."""
        new_component = DNComponent(attribute=attribute, value=value)
        return LdapDn(components=[new_component, *self.components])

    def replace_base_dn(self, old_base: LdapDn, new_base: LdapDn) -> LdapDn:
        """Replace base DN portion with new base DN."""
        if not self.is_child_of(old_base):
            msg = "DN is not a child of the specified base DN"
            raise ValueError(msg)

        # Keep the relative components and add new base
        relative_components = self.components[: len(self.components) - len(old_base.components)]
        return LdapDn(components=relative_components + new_base.components)


@dataclass
class ConnectionProfile:
    """Connection profile for LDAP operations."""

    name: str
    host: str
    port: int
    bind_dn: str
    password: str
    base_dn: str
    use_ssl: bool = False
    timeout: int = DEFAULT_TIMEOUT_SECONDS

    def __post_init__(self) -> Any:
        """Validate profile after initialization."""
        if not self.name.strip():
            msg = "Profile name cannot be empty"
            raise ValueError(msg)

        if not self.host.strip():
            msg = "Host cannot be empty"
            raise ValueError(msg)

        if not TCP_PORT_MIN <= self.port <= TCP_PORT_MAX:
            msg = f"Port must be between {TCP_PORT_MIN} and {TCP_PORT_MAX}"
            raise ValueError(msg)

        if not self.bind_dn.strip():
            msg = "Bind DN cannot be empty"
            raise ValueError(msg)

        if self.timeout <= 0:
            msg = "Timeout must be positive"
            raise ValueError(msg)

    def to_ldap_url(self) -> str:
        """Generate LDAP URL from profile."""
        protocol = "ldaps" if self.use_ssl else "ldap"
        return f"{protocol}://{self.host}:{self.port}"


@dataclass
class TransformationRule:
    """Rule for transforming LDAP entries during migration."""

    name: str
    description: str
    source_pattern: str
    target_pattern: str
    attribute_mappings: dict[str, str]
    object_class_mappings: dict[str, str]
    enabled: bool = True

    def __post_init__(self) -> Any:
        """Validate rule after initialization."""
        if not self.name.strip():
            msg = "Rule name cannot be empty"
            raise ValueError(msg)

        if not self.source_pattern.strip():
            msg = "Source pattern cannot be empty"
            raise ValueError(msg)

        if not self.target_pattern.strip():
            msg = "Target pattern cannot be empty"
            raise ValueError(msg)


class SchemaCompatibility(StrEnum):
    """Schema compatibility levels."""

    FULL = "full"  # Fully compatible
    COMPATIBLE = "compatible"  # Compatible with minor adjustments
    REQUIRES_MAPPING = "requires_mapping"  # Requires attribute/objectclass mapping
    INCOMPATIBLE = "incompatible"  # Cannot be migrated


@dataclass
class SchemaAnalysisResult:
    """Result of schema compatibility analysis."""

    compatibility: SchemaCompatibility
    required_mappings: dict[str, str]
    missing_object_classes: list[str]
    missing_attributes: list[str]
    warnings: list[str]
    recommendations: list[str]

    @property
    def is_migration_possible(self) -> bool:
        """Check if migration is possible with this schema."""
        return self.compatibility != SchemaCompatibility.INCOMPATIBLE


@dataclass
class MigrationPlan:
    """Complete migration execution plan."""

    name: str
    description: str
    source_profile: ConnectionProfile
    target_profile: ConnectionProfile
    transformation_rules: list[TransformationRule]
    schema_analysis: SchemaAnalysisResult
    phases: list[str]
    estimated_duration: int | None = None  # seconds

    def __post_init__(self) -> Any:
        """Validate plan after initialization."""
        if not self.name.strip():
            msg = "Plan name cannot be empty"
            raise ValueError(msg)

        if not self.phases:
            msg = "Plan must have at least one phase"
            raise ValueError(msg)

        if not self.schema_analysis.is_migration_possible:
            msg = "Migration plan cannot be created with incompatible schema"
            raise ValueError(msg)

    @property
    def is_ready_for_execution(self) -> bool:
        """Check if plan is ready for execution."""
        return (
            self.schema_analysis.is_migration_possible
            and len(self.transformation_rules) > 0
            and len(self.phases) > 0
        )

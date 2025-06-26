"""LDAP Schema Service Implementation.

This module provides comprehensive LDAP schema management functionality based
on perl-ldap Net::LDAP::Schema with enterprise-grade Python enhancements.

The SchemaService enables discovery, validation, and manipulation of LDAP
directory schemas including object classes, attributes, and syntaxes.

Architecture:
    - SchemaService: Main service for schema operations
    - LDAPSchema: Comprehensive schema representation
    - ObjectClassInfo: Object class definitions and inheritance
    - AttributeInfo: Attribute type definitions and constraints

Usage Example:
    >>> from ldap_core_shared.services.schema import SchemaService
    >>>
    >>> # Discover and load schema
    >>> service = SchemaService(connection)
    >>> schema = await service.load_schema()
    >>> print(f"Object classes: {len(schema.object_classes)}")
    >>> print(f"Attributes: {len(schema.attributes)}")
    >>>
    >>> # Validate object class usage
    >>> validation = service.validate_object_class("person", ["cn", "sn", "mail"])
    >>> if not validation.is_valid:
    ...     print(f"Validation errors: {validation.errors}")

References:
    - perl-ldap: lib/Net/LDAP/Schema.pm
    - RFC 4512: LDAP Directory Information Models
    - RFC 4517: LDAP Syntaxes and Matching Rules
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Any, Optional

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from datetime import datetime


class AttributeUsage(Enum):
    """LDAP attribute usage types."""

    USER_APPLICATIONS = "userApplications"
    DIRECTORY_OPERATION = "directoryOperation"
    DISTRIBUTED_OPERATION = "distributedOperation"
    DSA_OPERATION = "dsaOperation"


class ObjectClassType(Enum):
    """LDAP object class types."""

    STRUCTURAL = "STRUCTURAL"
    AUXILIARY = "AUXILIARY"
    ABSTRACT = "ABSTRACT"


class AttributeInfo(BaseModel):
    """Information about LDAP attribute types."""

    name: str = Field(description="Primary attribute name")

    aliases: list[str] = Field(
        default_factory=list, description="Alternative names for the attribute",
    )

    oid: str = Field(description="Object identifier for the attribute")

    description: Optional[str] = Field(
        default=None, description="Human-readable description",
    )

    syntax: str = Field(description="Attribute syntax OID")

    syntax_name: Optional[str] = Field(
        default=None, description="Human-readable syntax name",
    )

    equality_rule: Optional[str] = Field(
        default=None, description="Equality matching rule OID",
    )

    ordering_rule: Optional[str] = Field(
        default=None, description="Ordering matching rule OID",
    )

    substring_rule: Optional[str] = Field(
        default=None, description="Substring matching rule OID",
    )

    usage: AttributeUsage = Field(
        default=AttributeUsage.USER_APPLICATIONS, description="Attribute usage type",
    )

    is_single_valued: bool = Field(
        default=False, description="Whether attribute allows only single value",
    )

    is_user_modifiable: bool = Field(
        default=True, description="Whether attribute can be modified by users",
    )

    is_operational: bool = Field(
        default=False, description="Whether attribute is operational",
    )

    superior: Optional[str] = Field(default=None, description="Superior attribute type")

    def get_all_names(self) -> list[str]:
        """Get all names (primary + aliases) for this attribute."""
        return [self.name, *self.aliases]

    def is_numeric(self) -> bool:
        """Check if attribute has numeric syntax."""
        numeric_syntaxes = {
            "1.3.6.1.4.1.1466.115.121.1.27",  # Integer
            "1.3.6.1.4.1.1466.115.121.1.36",  # Numeric String
        }
        return self.syntax in numeric_syntaxes

    def is_binary(self) -> bool:
        """Check if attribute has binary syntax."""
        binary_syntaxes = {
            "1.3.6.1.4.1.1466.115.121.1.5",  # Binary
            "1.3.6.1.4.1.1466.115.121.1.8",  # Certificate
            "1.3.6.1.4.1.1466.115.121.1.9",  # Certificate List
            "1.3.6.1.4.1.1466.115.121.1.28",  # JPEG
            "1.3.6.1.4.1.1466.115.121.1.40",  # Octet String
        }
        return self.syntax in binary_syntaxes

    def supports_ordering(self) -> bool:
        """Check if attribute supports ordering operations."""
        return self.ordering_rule is not None

    def supports_substring(self) -> bool:
        """Check if attribute supports substring matching."""
        return self.substring_rule is not None


class ObjectClassInfo(BaseModel):
    """Information about LDAP object classes."""

    name: str = Field(description="Primary object class name")

    aliases: list[str] = Field(
        default_factory=list, description="Alternative names for the object class",
    )

    oid: str = Field(description="Object identifier for the object class")

    description: Optional[str] = Field(
        default=None, description="Human-readable description",
    )

    type: ObjectClassType = Field(description="Object class type")

    superior_classes: list[str] = Field(
        default_factory=list, description="Superior object classes",
    )

    must_attributes: list[str] = Field(
        default_factory=list, description="Required attributes",
    )

    may_attributes: list[str] = Field(
        default_factory=list, description="Optional attributes",
    )

    is_obsolete: bool = Field(default=False, description="Whether class is obsolete")

    def get_all_names(self) -> list[str]:
        """Get all names (primary + aliases) for this object class."""
        return [self.name, *self.aliases]

    def get_all_attributes(self) -> set[str]:
        """Get all attributes (must + may) for this object class."""
        return set(self.must_attributes + self.may_attributes)

    def is_structural(self) -> bool:
        """Check if this is a structural object class."""
        return self.type == ObjectClassType.STRUCTURAL

    def is_auxiliary(self) -> bool:
        """Check if this is an auxiliary object class."""
        return self.type == ObjectClassType.AUXILIARY

    def is_abstract(self) -> bool:
        """Check if this is an abstract object class."""
        return self.type == ObjectClassType.ABSTRACT


class SyntaxInfo(BaseModel):
    """Information about LDAP syntaxes."""

    oid: str = Field(description="Syntax OID")

    name: Optional[str] = Field(default=None, description="Human-readable name")

    description: Optional[str] = Field(default=None, description="Syntax description")

    is_human_readable: bool = Field(
        default=True, description="Whether syntax is human-readable",
    )


class MatchingRuleInfo(BaseModel):
    """Information about LDAP matching rules."""

    oid: str = Field(description="Matching rule OID")

    name: Optional[str] = Field(default=None, description="Human-readable name")

    description: Optional[str] = Field(
        default=None, description="Matching rule description",
    )

    syntax: str = Field(description="Associated syntax OID")

    is_obsolete: bool = Field(default=False, description="Whether rule is obsolete")


class SchemaValidationResult(BaseModel):
    """Result of schema validation operation."""

    is_valid: bool = Field(description="Whether validation passed")

    errors: list[str] = Field(default_factory=list, description="Validation errors")

    warnings: list[str] = Field(default_factory=list, description="Validation warnings")

    missing_attributes: list[str] = Field(
        default_factory=list, description="Missing required attributes",
    )

    invalid_attributes: list[str] = Field(
        default_factory=list, description="Invalid or unknown attributes",
    )

    def add_error(self, message: str) -> None:
        """Add validation error."""
        self.errors.append(message)
        self.is_valid = False

    def add_warning(self, message: str) -> None:
        """Add validation warning."""
        self.warnings.append(message)

    def has_errors(self) -> bool:
        """Check if validation has errors."""
        return len(self.errors) > 0

    def has_warnings(self) -> bool:
        """Check if validation has warnings."""
        return len(self.warnings) > 0


class LDAPSchema(BaseModel):
    """Comprehensive LDAP schema representation."""

    # Schema metadata
    schema_dn: Optional[str] = Field(
        default=None, description="Schema naming context DN",
    )

    modify_timestamp: Optional[datetime] = Field(
        default=None, description="Last schema modification timestamp",
    )

    server_vendor: Optional[str] = Field(default=None, description="LDAP server vendor")

    schema_version: Optional[str] = Field(default=None, description="Schema version")

    # Schema components
    object_classes: dict[str, ObjectClassInfo] = Field(
        default_factory=dict, description="Object class definitions by name",
    )

    attributes: dict[str, AttributeInfo] = Field(
        default_factory=dict, description="Attribute type definitions by name",
    )

    syntaxes: dict[str, SyntaxInfo] = Field(
        default_factory=dict, description="Syntax definitions by OID",
    )

    matching_rules: dict[str, MatchingRuleInfo] = Field(
        default_factory=dict, description="Matching rule definitions by OID",
    )

    # Aliases and cross-references
    object_class_aliases: dict[str, str] = Field(
        default_factory=dict, description="Object class alias to primary name mapping",
    )

    attribute_aliases: dict[str, str] = Field(
        default_factory=dict, description="Attribute alias to primary name mapping",
    )

    def get_object_class(self, name: str) -> Optional[ObjectClassInfo]:
        """Get object class by name or alias."""
        # Try primary name first
        if name in self.object_classes:
            return self.object_classes[name]

        # Try alias
        primary_name = self.object_class_aliases.get(name.lower())
        if primary_name:
            return self.object_classes.get(primary_name)

        return None

    def get_attribute(self, name: str) -> Optional[AttributeInfo]:
        """Get attribute by name or alias."""
        # Try primary name first
        if name in self.attributes:
            return self.attributes[name]

        # Try alias
        primary_name = self.attribute_aliases.get(name.lower())
        if primary_name:
            return self.attributes.get(primary_name)

        return None

    def get_syntax(self, oid: str) -> Optional[SyntaxInfo]:
        """Get syntax by OID."""
        return self.syntaxes.get(oid)

    def get_matching_rule(self, oid: str) -> Optional[MatchingRuleInfo]:
        """Get matching rule by OID."""
        return self.matching_rules.get(oid)

    def has_object_class(self, name: str) -> bool:
        """Check if object class exists."""
        return self.get_object_class(name) is not None

    def has_attribute(self, name: str) -> bool:
        """Check if attribute exists."""
        return self.get_attribute(name) is not None

    def get_structural_object_classes(self) -> list[ObjectClassInfo]:
        """Get all structural object classes."""
        return [oc for oc in self.object_classes.values() if oc.is_structural()]

    def get_auxiliary_object_classes(self) -> list[ObjectClassInfo]:
        """Get all auxiliary object classes."""
        return [oc for oc in self.object_classes.values() if oc.is_auxiliary()]

    def get_user_attributes(self) -> list[AttributeInfo]:
        """Get all user application attributes."""
        return [
            attr
            for attr in self.attributes.values()
            if attr.usage == AttributeUsage.USER_APPLICATIONS
        ]

    def get_operational_attributes(self) -> list[AttributeInfo]:
        """Get all operational attributes."""
        return [attr for attr in self.attributes.values() if attr.is_operational]

    def get_statistics(self) -> dict[str, int]:
        """Get schema statistics."""
        return {
            "object_classes": len(self.object_classes),
            "attributes": len(self.attributes),
            "syntaxes": len(self.syntaxes),
            "matching_rules": len(self.matching_rules),
            "structural_classes": len(self.get_structural_object_classes()),
            "auxiliary_classes": len(self.get_auxiliary_object_classes()),
            "user_attributes": len(self.get_user_attributes()),
            "operational_attributes": len(self.get_operational_attributes()),
        }


class SchemaService:
    """Service for LDAP schema management and validation.

    This service provides comprehensive schema management functionality for
    discovering, loading, and validating LDAP directory schemas.

    Example:
        >>> service = SchemaService(connection)
        >>> schema = await service.load_schema()
        >>> print(f"Schema contains {len(schema.object_classes)} object classes")
        >>>
        >>> # Validate entry against schema
        >>> validation = service.validate_entry("person", {"cn": "John", "sn": "Doe"})
        >>> if validation.is_valid:
        ...     print("Entry is valid")
    """

    def __init__(self, connection: Any) -> None:
        """Initialize schema service.

        Args:
            connection: Active LDAP connection
        """
        self._connection = connection
        self._cached_schema: Optional[LDAPSchema] = None
        self._schema_dn: Optional[str] = None

    async def load_schema(self, force_refresh: bool = False) -> LDAPSchema:
        """Load complete LDAP schema from directory.

        Args:
            force_refresh: Force refresh of cached schema

        Returns:
            Complete LDAP schema

        Raises:
            NotImplementedError: Schema loading not yet implemented
        """
        if self._cached_schema and not force_refresh:
            return self._cached_schema

        # TODO: Implement actual schema loading
        # This is a stub implementation
        msg = (
            "Schema loading requires connection manager integration. "
            "Implement schema DN discovery and schema entry parsing."
        )
        raise NotImplementedError(msg)

    def validate_entry(
        self, object_class: str, attributes: dict[str, Any],
    ) -> SchemaValidationResult:
        """Validate entry against schema.

        Args:
            object_class: Primary object class for the entry
            attributes: Entry attributes to validate

        Returns:
            Validation result with errors and warnings
        """
        result = SchemaValidationResult(is_valid=True)

        if not self._cached_schema:
            result.add_error("Schema not loaded - call load_schema() first")
            return result

        # Get object class info
        oc_info = self._cached_schema.get_object_class(object_class)
        if not oc_info:
            result.add_error(f"Unknown object class: {object_class}")
            return result

        # Validate required attributes
        for must_attr in oc_info.must_attributes:
            if must_attr not in attributes:
                result.missing_attributes.append(must_attr)
                result.add_error(f"Missing required attribute: {must_attr}")

        # Validate attribute existence in schema
        all_allowed_attrs = oc_info.get_all_attributes()
        for attr_name in attributes:
            if attr_name not in all_allowed_attrs:
                # Check if it's a valid attribute in schema
                attr_info = self._cached_schema.get_attribute(attr_name)
                if not attr_info:
                    result.invalid_attributes.append(attr_name)
                    result.add_warning(f"Unknown attribute: {attr_name}")

        return result

    def validate_object_class(
        self, object_class: str, provided_attributes: list[str],
    ) -> SchemaValidationResult:
        """Validate object class usage with provided attributes.

        Args:
            object_class: Object class to validate
            provided_attributes: List of attributes that will be provided

        Returns:
            Validation result
        """
        result = SchemaValidationResult(is_valid=True)

        if not self._cached_schema:
            result.add_error("Schema not loaded - call load_schema() first")
            return result

        oc_info = self._cached_schema.get_object_class(object_class)
        if not oc_info:
            result.add_error(f"Unknown object class: {object_class}")
            return result

        # Check required attributes
        for must_attr in oc_info.must_attributes:
            if must_attr not in provided_attributes:
                result.missing_attributes.append(must_attr)
                result.add_error(f"Missing required attribute: {must_attr}")

        # Check for invalid attributes
        allowed_attrs = oc_info.get_all_attributes()
        for attr in provided_attributes:
            if attr not in allowed_attrs:
                result.invalid_attributes.append(attr)
                result.add_warning(f"Attribute not allowed by object class: {attr}")

        return result

    def get_required_attributes(self, object_class: str) -> list[str]:
        """Get required attributes for object class.

        Args:
            object_class: Object class name

        Returns:
            List of required attribute names
        """
        if not self._cached_schema:
            return []

        oc_info = self._cached_schema.get_object_class(object_class)
        return oc_info.must_attributes if oc_info else []

    def get_allowed_attributes(self, object_class: str) -> list[str]:
        """Get all allowed attributes for object class.

        Args:
            object_class: Object class name

        Returns:
            List of allowed attribute names (must + may)
        """
        if not self._cached_schema:
            return []

        oc_info = self._cached_schema.get_object_class(object_class)
        return list(oc_info.get_all_attributes() if oc_info else [])

    def is_attribute_required(self, object_class: str, attribute: str) -> bool:
        """Check if attribute is required for object class.

        Args:
            object_class: Object class name
            attribute: Attribute name

        Returns:
            True if attribute is required
        """
        if not self._cached_schema:
            return False

        oc_info = self._cached_schema.get_object_class(object_class)
        return attribute in oc_info.must_attributes if oc_info else False

    def is_attribute_allowed(self, object_class: str, attribute: str) -> bool:
        """Check if attribute is allowed for object class.

        Args:
            object_class: Object class name
            attribute: Attribute name

        Returns:
            True if attribute is allowed
        """
        if not self._cached_schema:
            return False

        oc_info = self._cached_schema.get_object_class(object_class)
        return attribute in oc_info.get_all_attributes() if oc_info else False

    def get_attribute_syntax(self, attribute: str) -> Optional[str]:
        """Get syntax OID for attribute.

        Args:
            attribute: Attribute name

        Returns:
            Syntax OID or None if attribute not found
        """
        if not self._cached_schema:
            return None

        attr_info = self._cached_schema.get_attribute(attribute)
        return attr_info.syntax if attr_info else None

    def is_attribute_binary(self, attribute: str) -> bool:
        """Check if attribute has binary syntax.

        Args:
            attribute: Attribute name

        Returns:
            True if attribute is binary
        """
        if not self._cached_schema:
            return False

        attr_info = self._cached_schema.get_attribute(attribute)
        return attr_info.is_binary() if attr_info else False

    def is_attribute_single_valued(self, attribute: str) -> bool:
        """Check if attribute is single-valued.

        Args:
            attribute: Attribute name

        Returns:
            True if attribute is single-valued
        """
        if not self._cached_schema:
            return False

        attr_info = self._cached_schema.get_attribute(attribute)
        return attr_info.is_single_valued if attr_info else False

    def get_object_class_hierarchy(self, object_class: str) -> list[str]:
        """Get object class inheritance hierarchy.

        Args:
            object_class: Object class name

        Returns:
            List of object classes in inheritance order
        """
        if not self._cached_schema:
            return []

        hierarchy = []
        current = object_class

        # Avoid infinite loops with visited tracking
        visited = set()

        while current and current not in visited:
            visited.add(current)
            oc_info = self._cached_schema.get_object_class(current)

            if not oc_info:
                break

            hierarchy.append(current)

            # Move to superior class
            if oc_info.superior_classes:
                current = oc_info.superior_classes[0]  # Take first superior
            else:
                break

        return hierarchy

    def _parse_schema_entry(self, schema_entry: dict[str, Any]) -> LDAPSchema:
        """Parse schema entry into LDAPSchema object.

        Args:
            schema_entry: Raw schema entry attributes

        Returns:
            Parsed LDAP schema
        """
        schema = LDAPSchema()

        # Parse object classes
        object_classes = schema_entry.get("objectClasses", [])
        for oc_def in object_classes:
            oc_info = self._parse_object_class_definition(oc_def)
            if oc_info:
                schema.object_classes[oc_info.name] = oc_info
                # Add aliases
                for alias in oc_info.aliases:
                    schema.object_class_aliases[alias.lower()] = oc_info.name

        # Parse attribute types
        attribute_types = schema_entry.get("attributeTypes", [])
        for attr_def in attribute_types:
            attr_info = self._parse_attribute_definition(attr_def)
            if attr_info:
                schema.attributes[attr_info.name] = attr_info
                # Add aliases
                for alias in attr_info.aliases:
                    schema.attribute_aliases[alias.lower()] = attr_info.name

        # Parse syntaxes
        syntaxes = schema_entry.get("ldapSyntaxes", [])
        for syntax_def in syntaxes:
            syntax_info = self._parse_syntax_definition(syntax_def)
            if syntax_info:
                schema.syntaxes[syntax_info.oid] = syntax_info

        # Parse matching rules
        matching_rules = schema_entry.get("matchingRules", [])
        for rule_def in matching_rules:
            rule_info = self._parse_matching_rule_definition(rule_def)
            if rule_info:
                schema.matching_rules[rule_info.oid] = rule_info

        return schema

    def _parse_object_class_definition(
        self, definition: str,
    ) -> Optional[ObjectClassInfo]:
        """Parse object class definition string."""
        # This is a simplified parser - real implementation would be more comprehensive
        # TODO: Implement full RFC 4512 object class definition parsing
        return None

    def _parse_attribute_definition(self, definition: str) -> Optional[AttributeInfo]:
        """Parse attribute type definition string."""
        # This is a simplified parser - real implementation would be more comprehensive
        # TODO: Implement full RFC 4512 attribute type definition parsing
        return None

    def _parse_syntax_definition(self, definition: str) -> Optional[SyntaxInfo]:
        """Parse syntax definition string."""
        # This is a simplified parser - real implementation would be more comprehensive
        # TODO: Implement full RFC 4512 syntax definition parsing
        return None

    def _parse_matching_rule_definition(
        self, definition: str,
    ) -> Optional[MatchingRuleInfo]:
        """Parse matching rule definition string."""
        # This is a simplified parser - real implementation would be more comprehensive
        # TODO: Implement full RFC 4512 matching rule definition parsing
        return None


# Convenience functions
async def load_schema(connection: Any) -> LDAPSchema:
    """Load LDAP schema from connection.

    Args:
        connection: LDAP connection

    Returns:
        Complete LDAP schema
    """
    service = SchemaService(connection)
    return await service.load_schema()


def validate_entry_schema(
    schema: LDAPSchema, object_class: str, attributes: dict[str, Any],
) -> SchemaValidationResult:
    """Validate entry against schema.

    Args:
        schema: LDAP schema
        object_class: Primary object class
        attributes: Entry attributes

    Returns:
        Validation result
    """
    # Create temporary service with pre-loaded schema
    service = SchemaService(None)
    service._cached_schema = schema
    return service.validate_entry(object_class, attributes)


def get_object_class_info(schema: LDAPSchema, name: str) -> Optional[ObjectClassInfo]:
    """Get object class information from schema.

    Args:
        schema: LDAP schema
        name: Object class name

    Returns:
        Object class information or None
    """
    return schema.get_object_class(name)


def get_attribute_info(schema: LDAPSchema, name: str) -> Optional[AttributeInfo]:
    """Get attribute information from schema.

    Args:
        schema: LDAP schema
        name: Attribute name

    Returns:
        Attribute information or None
    """
    return schema.get_attribute(name)

# TODO: Integration points for implementation:
#
# 1. Schema Discovery and Loading:
#    - Implement Root DSE integration to discover schema DN
#    - Parse schema entries from subschema subentry
#    - Handle different schema formats (RFC 4512, vendor-specific)
#
# 2. Schema Definition Parsing:
#    - Complete RFC 4512 compliant parsers for all schema elements
#    - Handle vendor extensions and custom schema elements
#    - Support for schema modification tracking
#
# 3. Schema Validation Engine:
#    - Advanced validation rules for complex scenarios
#    - Support for multiple object classes per entry
#    - Auxiliary object class validation
#    - Inheritance chain validation
#
# 4. Schema Evolution and Versioning:
#    - Schema change detection and notification
#    - Version compatibility checking
#    - Migration assistance for schema updates
#
# 5. Performance Optimization:
#    - Schema caching with intelligent invalidation
#    - Lazy loading of schema components
#    - Memory-efficient schema representation
#
# 6. Integration Features:
#    - Filter validation using schema information
#    - Entry validation in modification operations
#    - Schema-aware attribute value validation
#    - Object class hierarchy navigation
#
# 7. Testing Requirements:
#    - Unit tests for all schema parsing scenarios
#    - Integration tests with different LDAP server schemas
#    - Performance tests for large schema validation
#    - Edge case tests for malformed schema definitions

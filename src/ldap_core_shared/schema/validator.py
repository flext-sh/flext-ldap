"""Schema Validator - Comprehensive LDAP schema validation.

This module provides enterprise-grade schema validation capabilities including
RFC compliance checking, dependency validation, and conflict detection.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from ldap_core_shared.domain.results import LDAPValidationResult

if TYPE_CHECKING:
    from ldap_core_shared.schema.parser import AttributeType, ObjectClass, ParsedSchema

logger = logging.getLogger(__name__)


class SchemaValidationConfig(BaseModel):
    """Configuration for schema validation operations."""

    model_config = ConfigDict(strict=True, extra="forbid")

    check_rfc_compliance: bool = Field(
        default=True,
        description="Check RFC 2252 compliance",
    )
    check_dependencies: bool = Field(
        default=True,
        description="Check schema dependencies",
    )
    check_name_conflicts: bool = Field(
        default=True,
        description="Check for name conflicts",
    )
    check_oid_uniqueness: bool = Field(default=True, description="Check OID uniqueness")
    allow_obsolete_elements: bool = Field(
        default=False,
        description="Allow obsolete schema elements",
    )


class SchemaValidator:
    """Enterprise-grade schema validator with RFC compliance checking."""

    def __init__(self, config: SchemaValidationConfig | None = None) -> None:
        """Initialize schema validator with configuration."""
        self.config = config or SchemaValidationConfig()

    def validate_schema(self, schema: ParsedSchema) -> LDAPValidationResult:
        """Validate complete parsed schema.

        Args:
            schema: Parsed schema to validate

        Returns:
            Validation result with errors and warnings
        """
        errors = []
        warnings = []

        # Validate attribute types
        for attr_type in schema.attribute_types.values():
            result = self.validate_attribute_type(attr_type, schema)
            errors.extend(result.errors)
            warnings.extend(result.warnings)

        # Validate object classes
        for obj_class in schema.object_classes.values():
            result = self.validate_object_class(obj_class, schema)
            errors.extend(result.errors)
            warnings.extend(result.warnings)

        # Global validations
        if self.config.check_oid_uniqueness:
            oid_errors = self._check_oid_uniqueness(schema)
            errors.extend(oid_errors)

        if self.config.check_name_conflicts:
            name_errors = self._check_name_conflicts(schema)
            errors.extend(name_errors)

        return LDAPValidationResult(
            is_valid=len(errors) == 0,
            error_count=len(errors),
            warning_count=len(warnings),
            errors=errors,
            warnings=warnings,
        )

    def validate_attribute_type(
        self,
        attr_type: AttributeType,
        schema: ParsedSchema,
    ) -> LDAPValidationResult:
        """Validate single attribute type."""
        errors = []
        warnings = []

        # Check RFC compliance
        if self.config.check_rfc_compliance:
            rfc_errors = self._check_attribute_rfc_compliance(attr_type)
            errors.extend(rfc_errors)

        # Check dependencies
        if self.config.check_dependencies:
            dep_errors = self._check_attribute_dependencies(attr_type, schema)
            errors.extend(dep_errors)

        # Check for obsolete
        if not self.config.allow_obsolete_elements and attr_type.obsolete:
            warnings.append(f"Attribute type {attr_type.oid} is marked as obsolete")

        return LDAPValidationResult(
            is_valid=len(errors) == 0,
            error_count=len(errors),
            warning_count=len(warnings),
            errors=errors,
            warnings=warnings,
        )

    def validate_object_class(
        self,
        obj_class: ObjectClass,
        schema: ParsedSchema,
    ) -> LDAPValidationResult:
        """Validate single object class."""
        errors = []
        warnings = []

        # Check RFC compliance
        if self.config.check_rfc_compliance:
            rfc_errors = self._check_object_class_rfc_compliance(obj_class)
            errors.extend(rfc_errors)

        # Check dependencies
        if self.config.check_dependencies:
            dep_errors = self._check_object_class_dependencies(obj_class, schema)
            errors.extend(dep_errors)

        # Check for obsolete
        if not self.config.allow_obsolete_elements and obj_class.obsolete:
            warnings.append(f"Object class {obj_class.oid} is marked as obsolete")

        return LDAPValidationResult(
            is_valid=len(errors) == 0,
            error_count=len(errors),
            warning_count=len(warnings),
            errors=errors,
            warnings=warnings,
        )

    def _check_attribute_rfc_compliance(self, attr_type: AttributeType) -> list[str]:
        """Check attribute type RFC 2252 compliance."""
        errors = []

        # Check OID format
        if not self._is_valid_oid(attr_type.oid):
            errors.append(f"Invalid OID format: {attr_type.oid}")

        # Check names
        if not attr_type.names:
            errors.append(f"Attribute type {attr_type.oid} must have at least one name")

        for name in attr_type.names:
            if not self._is_valid_attribute_name(name):
                errors.append(f"Invalid attribute name: {name}")

        # Check usage values
        valid_usages = [
            "userApplications",
            "directoryOperation",
            "distributedOperation",
            "dSAOperation",
        ]
        if attr_type.usage not in valid_usages:
            errors.append(f"Invalid usage value: {attr_type.usage}")

        return errors

    def _check_object_class_rfc_compliance(self, obj_class: ObjectClass) -> list[str]:
        """Check object class RFC 2252 compliance."""
        errors = []

        # Check OID format
        if not self._is_valid_oid(obj_class.oid):
            errors.append(f"Invalid OID format: {obj_class.oid}")

        # Check names
        if not obj_class.names:
            errors.append(f"Object class {obj_class.oid} must have at least one name")

        for name in obj_class.names:
            if not self._is_valid_object_class_name(name):
                errors.append(f"Invalid object class name: {name}")

        # Check class type
        valid_types = ["STRUCTURAL", "AUXILIARY", "ABSTRACT"]
        if obj_class.class_type not in valid_types:
            errors.append(f"Invalid object class type: {obj_class.class_type}")

        return errors

    def _check_attribute_dependencies(
        self,
        attr_type: AttributeType,
        schema: ParsedSchema,
    ) -> list[str]:
        """Check attribute type dependencies."""
        errors = []

        # Check superior attribute type
        if attr_type.superior:
            if not self._find_attribute_by_name(attr_type.superior, schema):
                errors.append(
                    f"Superior attribute type not found: {attr_type.superior}",
                )

        # Check syntax (if we have syntax definitions)
        if attr_type.syntax and schema.syntax_definitions:
            if attr_type.syntax not in schema.syntax_definitions:
                errors.append(f"Syntax definition not found: {attr_type.syntax}")

        # Check matching rules (if we have them)
        if attr_type.equality_rule and schema.matching_rules:
            if not self._find_matching_rule_by_name(attr_type.equality_rule, schema):
                errors.append(
                    f"Equality matching rule not found: {attr_type.equality_rule}",
                )

        return errors

    def _check_object_class_dependencies(
        self,
        obj_class: ObjectClass,
        schema: ParsedSchema,
    ) -> list[str]:
        """Check object class dependencies."""
        errors = []

        # Check superior object classes
        for superior in obj_class.superior_classes:
            if not self._find_object_class_by_name(superior, schema):
                errors.append(f"Superior object class not found: {superior}")

        # Check required attributes
        for attr_name in obj_class.must_attributes:
            if not self._find_attribute_by_name(attr_name, schema):
                errors.append(f"Required attribute not found: {attr_name}")

        # Check optional attributes
        for attr_name in obj_class.may_attributes:
            if not self._find_attribute_by_name(attr_name, schema):
                errors.append(f"Optional attribute not found: {attr_name}")

        return errors

    def _check_oid_uniqueness(self, schema: ParsedSchema) -> list[str]:
        """Check that all OIDs are unique across schema elements."""
        errors = []
        all_oids = set()

        # Check attribute types
        for oid in schema.attribute_types:
            if oid in all_oids:
                errors.append(f"Duplicate OID found: {oid}")
            all_oids.add(oid)

        # Check object classes
        for oid in schema.object_classes:
            if oid in all_oids:
                errors.append(f"Duplicate OID found: {oid}")
            all_oids.add(oid)

        # Check syntax definitions
        for oid in schema.syntax_definitions:
            if oid in all_oids:
                errors.append(f"Duplicate OID found: {oid}")
            all_oids.add(oid)

        # Check matching rules
        for oid in schema.matching_rules:
            if oid in all_oids:
                errors.append(f"Duplicate OID found: {oid}")
            all_oids.add(oid)

        return errors

    def _check_name_conflicts(self, schema: ParsedSchema) -> list[str]:
        """Check for name conflicts between schema elements."""
        errors = []
        all_names = {}

        # Collect all names
        for attr_type in schema.attribute_types.values():
            for name in attr_type.names:
                name_lower = name.lower()
                if name_lower in all_names:
                    errors.append(
                        f"Name conflict: '{name}' used in both {all_names[name_lower]} and attribute type {attr_type.oid}",
                    )
                else:
                    all_names[name_lower] = f"attribute type {attr_type.oid}"

        for obj_class in schema.object_classes.values():
            for name in obj_class.names:
                name_lower = name.lower()
                if name_lower in all_names:
                    errors.append(
                        f"Name conflict: '{name}' used in both {all_names[name_lower]} and object class {obj_class.oid}",
                    )
                else:
                    all_names[name_lower] = f"object class {obj_class.oid}"

        return errors

    def _is_valid_oid(self, oid: str) -> bool:
        """Check if OID format is valid."""
        import re

        return bool(re.match(r"^[0-9]+(\.[0-9]+)*$", oid))

    def _is_valid_attribute_name(self, name: str) -> bool:
        """Check if attribute name format is valid."""
        import re

        return bool(re.match(r"^[a-zA-Z][a-zA-Z0-9-]*$", name))

    def _is_valid_object_class_name(self, name: str) -> bool:
        """Check if object class name format is valid."""
        import re

        return bool(re.match(r"^[a-zA-Z][a-zA-Z0-9-]*$", name))

    def _find_attribute_by_name(
        self,
        name: str,
        schema: ParsedSchema,
    ) -> AttributeType | None:
        """Find attribute type by name."""
        name_lower = name.lower()
        for attr_type in schema.attribute_types.values():
            if any(n.lower() == name_lower for n in attr_type.names):
                return attr_type
        return None

    def _find_object_class_by_name(
        self,
        name: str,
        schema: ParsedSchema,
    ) -> ObjectClass | None:
        """Find object class by name."""
        name_lower = name.lower()
        for obj_class in schema.object_classes.values():
            if any(n.lower() == name_lower for n in obj_class.names):
                return obj_class
        return None

    def _find_matching_rule_by_name(self, name: str, schema: ParsedSchema) -> bool:
        """Check if matching rule exists by name."""
        name_lower = name.lower()
        for mr in schema.matching_rules.values():
            if any(n.lower() == name_lower for n in mr.names):
                return True
        return False

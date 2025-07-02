"""Schema Comparator - Compare LDAP schemas and find differences.

This module provides capabilities to compare schemas from different sources
and identify differences for migration planning and validation.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from flext_ldap.domain.results import LDAPOperationResult

if TYPE_CHECKING:
    from flext_ldaper import AttributeType, ObjectClass, ParsedSchema

logger = logging.getLogger(__name__)


class DifferenceType(Enum):
    """Types of schema differences."""

    ADDED = "added"
    REMOVED = "removed"
    MODIFIED = "modified"
    CONFLICT = "conflict"


class SchemaDifference(BaseModel):
    """Represents a difference between two schemas."""

    model_config = ConfigDict(strict=True, extra="forbid")

    element_type: str = Field(..., description="Type of schema element")
    element_name: str = Field(..., description="Name or OID of element")
    difference_type: DifferenceType = Field(..., description="Type of difference")
    source_definition: str | None = Field(
        default=None,
        description="Definition in source schema",
    )
    target_definition: str | None = Field(
        default=None,
        description="Definition in target schema",
    )
    description: str = Field(default="", description="Human-readable description")
    severity: str = Field(default="INFO", description="Severity level")


class SchemaComparisonResult(BaseModel):
    """Results from schema comparison."""

    model_config = ConfigDict(strict=True, extra="forbid")

    source_elements: int = Field(default=0, description="Number of elements in source")
    target_elements: int = Field(default=0, description="Number of elements in target")
    differences: list[SchemaDifference] = Field(
        default_factory=list,
        description="List of differences",
    )
    summary: dict[str, int] = Field(
        default_factory=dict,
        description="Summary statistics",
    )


class SchemaComparator:
    """Compare LDAP schemas and identify differences."""

    def __init__(self) -> None:
        """Initialize schema comparator."""

    def compare_schemas(
        self,
        source_schema: ParsedSchema,
        target_schema: ParsedSchema,
    ) -> LDAPOperationResult[SchemaComparisonResult]:
        """Compare two schemas and identify differences.

        Args:
            source_schema: Source schema to compare from
            target_schema: Target schema to compare to

        Returns:
            Operation result with comparison results

        """
        try:
            differences = []

            # Compare attribute types
            attr_diffs = self._compare_attribute_types(source_schema, target_schema)
            differences.extend(attr_diffs)

            # Compare object classes
            oc_diffs = self._compare_object_classes(source_schema, target_schema)
            differences.extend(oc_diffs)

            # Generate summary
            summary = self._generate_summary(differences)

            result = SchemaComparisonResult(
                source_elements=len(source_schema.attribute_types)
                + len(source_schema.object_classes),
                target_elements=len(target_schema.attribute_types)
                + len(target_schema.object_classes),
                differences=differences,
                summary=summary,
            )

            return LDAPOperationResult[SchemaComparisonResult](
                success=True,
                data=result,
                operation="compare_schemas",
            )

        except Exception as e:
            logger.exception("Failed to compare schemas")
            return LDAPOperationResult[SchemaComparisonResult](
                success=False,
                error_message=f"Comparison failed: {e!s}",
                operation="compare_schemas",
            )

    def _compare_attribute_types(
        self,
        source_schema: ParsedSchema,
        target_schema: ParsedSchema,
    ) -> list[SchemaDifference]:
        """Compare attribute types between schemas."""
        differences = []

        # Find attributes only in source (removed from target)
        for oid, attr_type in source_schema.attribute_types.items():
            if oid not in target_schema.attribute_types:
                # Check if it exists by name
                target_attr = self._find_attribute_by_name(attr_type, target_schema)
                if target_attr:
                    # OID changed but name exists
                    differences.append(
                        SchemaDifference(
                            element_type="attributeType",
                            element_name=attr_type.names[0] if attr_type.names else oid,
                            difference_type=DifferenceType.MODIFIED,
                            source_definition=f"OID: {oid}",
                            target_definition=f"OID: {target_attr.oid}",
                            description="OID changed",
                            severity="WARNING",
                        ),
                    )
                else:
                    differences.append(
                        SchemaDifference(
                            element_type="attributeType",
                            element_name=attr_type.names[0] if attr_type.names else oid,
                            difference_type=DifferenceType.REMOVED,
                            source_definition=f"OID: {oid}",
                            description="Attribute type removed",
                            severity="WARNING",
                        ),
                    )

        # Find attributes only in target (added to target)
        for oid, attr_type in target_schema.attribute_types.items():
            if oid not in source_schema.attribute_types:
                # Check if it exists by name in source
                source_attr = self._find_attribute_by_name(attr_type, source_schema)
                if not source_attr:
                    differences.append(
                        SchemaDifference(
                            element_type="attributeType",
                            element_name=attr_type.names[0] if attr_type.names else oid,
                            difference_type=DifferenceType.ADDED,
                            target_definition=f"OID: {oid}",
                            description="Attribute type added",
                            severity="INFO",
                        ),
                    )

        # Find modified attributes (same OID, different definition)
        for oid in source_schema.attribute_types:
            if oid in target_schema.attribute_types:
                source_attr = source_schema.attribute_types[oid]
                target_attr = target_schema.attribute_types[oid]

                if not self._attributes_equal(source_attr, target_attr):
                    differences.append(
                        SchemaDifference(
                            element_type="attributeType",
                            element_name=source_attr.names[0]
                            if source_attr.names
                            else oid,
                            difference_type=DifferenceType.MODIFIED,
                            source_definition=self._format_attribute_summary(
                                source_attr,
                            ),
                            target_definition=self._format_attribute_summary(
                                target_attr,
                            ),
                            description="Attribute type definition changed",
                            severity="WARNING",
                        ),
                    )

        return differences

    def _compare_object_classes(
        self,
        source_schema: ParsedSchema,
        target_schema: ParsedSchema,
    ) -> list[SchemaDifference]:
        """Compare object classes between schemas."""
        differences = []

        # Find object classes only in source (removed from target)
        for oid, obj_class in source_schema.object_classes.items():
            if oid not in target_schema.object_classes:
                target_oc = self._find_object_class_by_name(obj_class, target_schema)
                if target_oc:
                    differences.append(
                        SchemaDifference(
                            element_type="objectClass",
                            element_name=obj_class.names[0] if obj_class.names else oid,
                            difference_type=DifferenceType.MODIFIED,
                            source_definition=f"OID: {oid}",
                            target_definition=f"OID: {target_oc.oid}",
                            description="OID changed",
                            severity="WARNING",
                        ),
                    )
                else:
                    differences.append(
                        SchemaDifference(
                            element_type="objectClass",
                            element_name=obj_class.names[0] if obj_class.names else oid,
                            difference_type=DifferenceType.REMOVED,
                            source_definition=f"OID: {oid}",
                            description="Object class removed",
                            severity="WARNING",
                        ),
                    )

        # Find object classes only in target (added to target)
        for oid, obj_class in target_schema.object_classes.items():
            if oid not in source_schema.object_classes:
                source_oc = self._find_object_class_by_name(obj_class, source_schema)
                if not source_oc:
                    differences.append(
                        SchemaDifference(
                            element_type="objectClass",
                            element_name=obj_class.names[0] if obj_class.names else oid,
                            difference_type=DifferenceType.ADDED,
                            target_definition=f"OID: {oid}",
                            description="Object class added",
                            severity="INFO",
                        ),
                    )

        # Find modified object classes
        for oid in source_schema.object_classes:
            if oid in target_schema.object_classes:
                source_oc = source_schema.object_classes[oid]
                target_oc = target_schema.object_classes[oid]

                if not self._object_classes_equal(source_oc, target_oc):
                    differences.append(
                        SchemaDifference(
                            element_type="objectClass",
                            element_name=source_oc.names[0] if source_oc.names else oid,
                            difference_type=DifferenceType.MODIFIED,
                            source_definition=self._format_object_class_summary(
                                source_oc,
                            ),
                            target_definition=self._format_object_class_summary(
                                target_oc,
                            ),
                            description="Object class definition changed",
                            severity="WARNING",
                        ),
                    )

        return differences

    def _find_attribute_by_name(
        self,
        attr_type: AttributeType,
        schema: ParsedSchema,
    ) -> AttributeType | None:
        """Find attribute type by name in schema."""
        for attr in schema.attribute_types.values():
            if any(
                name.lower() in [n.lower() for n in attr_type.names]
                for name in attr.names
            ):
                return attr
        return None

    def _find_object_class_by_name(
        self,
        obj_class: ObjectClass,
        schema: ParsedSchema,
    ) -> ObjectClass | None:
        """Find object class by name in schema."""
        for oc in schema.object_classes.values():
            if any(
                name.lower() in [n.lower() for n in obj_class.names]
                for name in oc.names
            ):
                return oc
        return None

    def _attributes_equal(self, attr1: AttributeType, attr2: AttributeType) -> bool:
        """Check if two attribute types are equal."""
        return (
            attr1.names == attr2.names
            and attr1.description == attr2.description
            and attr1.syntax == attr2.syntax
            and attr1.equality_rule == attr2.equality_rule
            and attr1.single_value == attr2.single_value
            and attr1.usage == attr2.usage
        )

    def _object_classes_equal(self, oc1: ObjectClass, oc2: ObjectClass) -> bool:
        """Check if two object classes are equal."""
        return (
            oc1.names == oc2.names
            and oc1.description == oc2.description
            and oc1.class_type == oc2.class_type
            and set(oc1.superior_classes) == set(oc2.superior_classes)
            and set(oc1.must_attributes) == set(oc2.must_attributes)
            and set(oc1.may_attributes) == set(oc2.may_attributes)
        )

    def _format_attribute_summary(self, attr: AttributeType) -> str:
        """Format attribute type summary for display."""
        parts = []
        if attr.names:
            parts.append(f"NAME {attr.names[0]}")
        if attr.syntax:
            parts.append(f"SYNTAX {attr.syntax}")
        if attr.single_value:
            parts.append("SINGLE-VALUE")
        return " ".join(parts)

    def _format_object_class_summary(self, oc: ObjectClass) -> str:
        """Format object class summary for display."""
        parts = []
        if oc.names:
            parts.append(f"NAME {oc.names[0]}")
        parts.append(f"TYPE {oc.class_type}")
        if oc.must_attributes:
            parts.append(f"MUST {len(oc.must_attributes)} attrs")
        if oc.may_attributes:
            parts.append(f"MAY {len(oc.may_attributes)} attrs")
        return " ".join(parts)

    def _generate_summary(self, differences: list[SchemaDifference]) -> dict[str, int]:
        """Generate summary statistics from differences."""
        summary = {
            "total_differences": len(differences),
            "added": 0,
            "removed": 0,
            "modified": 0,
            "conflicts": 0,
            "attribute_types": 0,
            "object_classes": 0,
        }

        for diff in differences:
            summary[diff.difference_type.value] += 1
            summary[diff.element_type] += 1

        return summary

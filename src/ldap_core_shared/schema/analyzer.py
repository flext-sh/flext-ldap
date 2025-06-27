"""Schema Analyzer - Advanced schema analysis and optimization."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from ldap_core_shared.domain.results import LDAPOperationResult
from ldap_core_shared.utils.constants import DEFAULT_MAX_ITEMS, DEFAULT_TIMEOUT_SECONDS

# Constants for magic values
MIN_NAME_LENGTH = 3  # Minimum length for well-named identifiers

if TYPE_CHECKING:
    from ldap_core_shared.schema.parser import ParsedSchema

logger = logging.getLogger(__name__)


class SchemaAnalysisResult(BaseModel):
    """Results from schema analysis operations."""

    model_config = ConfigDict(strict=True, extra="forbid")

    complexity_score: float = Field(default=0.0, description="Schema complexity score")
    health_score: float = Field(default=0.0, description="Schema health score")
    optimization_recommendations: list[str] = Field(
        default_factory=list,
        description="Optimization recommendations",
    )
    statistics: dict[str, Any] = Field(
        default_factory=dict,
        description="Detailed statistics",
    )
    warnings: list[str] = Field(default_factory=list, description="Analysis warnings")


class SchemaAnalyzer:
    """Advanced schema analyzer for optimization and health assessment."""

    def __init__(self) -> None:
        """Initialize schema analyzer."""

    def analyze_schema(
        self,
        schema: ParsedSchema,
    ) -> LDAPOperationResult[SchemaAnalysisResult]:
        """Perform comprehensive schema analysis.

        Args:
            schema: Parsed schema to analyze

        Returns:
            Operation result with analysis results
        """
        try:
            # Calculate metrics
            complexity_score = self._calculate_complexity_score(schema)
            health_score = self._calculate_health_score(schema)
            recommendations = self._generate_recommendations(schema)
            statistics = self._generate_statistics(schema)
            warnings = self._generate_warnings(schema)

            result = SchemaAnalysisResult(
                complexity_score=complexity_score,
                health_score=health_score,
                optimization_recommendations=recommendations,
                statistics=statistics,
                warnings=warnings,
            )

            return LDAPOperationResult[SchemaAnalysisResult](
                success=True,
                data=result,
                operation="analyze_schema",
            )

        except Exception as e:
            logger.exception("Failed to analyze schema")
            return LDAPOperationResult[SchemaAnalysisResult](
                success=False,
                error_message=f"Analysis failed: {e!s}",
                operation="analyze_schema",
            )

    def _calculate_complexity_score(self, schema: ParsedSchema) -> float:
        """Calculate schema complexity score (0-DEFAULT_MAX_ITEMS)."""
        score = 0.0

        # Base complexity from element count
        total_elements = len(schema.attribute_types) + len(schema.object_classes)
        score += min(40, total_elements * 0.1)

        # Inheritance complexity
        inheritance_depth = 0
        for oc in schema.object_classes.values():
            if oc.superior_classes:
                inheritance_depth += len(oc.superior_classes)
        score += min(20, inheritance_depth * 0.5)

        # Attribute complexity
        total_attributes = sum(
            len(oc.must_attributes) + len(oc.may_attributes)
            for oc in schema.object_classes.values()
        )
        score += min(25, total_attributes * 0.02)

        # Syntax diversity
        unique_syntaxes = len(
            {attr.syntax for attr in schema.attribute_types.values() if attr.syntax},
        )
        score += min(15, unique_syntaxes * 0.5)

        return min(DEFAULT_MAX_ITEMS, score)

    def _calculate_health_score(self, schema: ParsedSchema) -> float:
        """Calculate schema health score (0-DEFAULT_MAX_ITEMS)."""
        score = DEFAULT_MAX_ITEMS

        # Penalize obsolete elements
        obsolete_attrs = sum(
            1 for attr in schema.attribute_types.values() if attr.obsolete
        )
        obsolete_ocs = sum(1 for oc in schema.object_classes.values() if oc.obsolete)
        total_obsolete = obsolete_attrs + obsolete_ocs
        total_elements = len(schema.attribute_types) + len(schema.object_classes)

        if total_elements > 0:
            obsolete_ratio = total_obsolete / total_elements
            score -= obsolete_ratio * DEFAULT_TIMEOUT_SECONDS

        # Penalize missing descriptions
        attrs_without_desc = sum(
            1 for attr in schema.attribute_types.values() if not attr.description
        )
        ocs_without_desc = sum(
            1 for oc in schema.object_classes.values() if not oc.description
        )

        if total_elements > 0:
            missing_desc_ratio = (
                attrs_without_desc + ocs_without_desc
            ) / total_elements
            score -= missing_desc_ratio * 20

        # Penalize attributes without syntax
        attrs_without_syntax = sum(
            1 for attr in schema.attribute_types.values() if not attr.syntax
        )

        if len(schema.attribute_types) > 0:
            no_syntax_ratio = attrs_without_syntax / len(schema.attribute_types)
            score -= no_syntax_ratio * 25

        # Reward proper naming conventions
        proper_names = 0
        total_names = 0

        for attr in schema.attribute_types.values():
            total_names += len(attr.names)
            proper_names += sum(1 for name in attr.names if self._is_well_named(name))

        for oc in schema.object_classes.values():
            total_names += len(oc.names)
            proper_names += sum(1 for name in oc.names if self._is_well_named(name))

        if total_names > 0:
            naming_score = (proper_names / total_names) * 10
            score += naming_score

        return max(0.0, min(DEFAULT_MAX_ITEMS, score))

    def _generate_recommendations(self, schema: ParsedSchema) -> list[str]:
        """Generate optimization recommendations."""
        recommendations = []

        # Check for obsolete elements
        obsolete_attrs = [
            attr for attr in schema.attribute_types.values() if attr.obsolete
        ]
        obsolete_ocs = [oc for oc in schema.object_classes.values() if oc.obsolete]

        if obsolete_attrs or obsolete_ocs:
            recommendations.append(
                f"Remove {len(obsolete_attrs + obsolete_ocs)} obsolete schema elements",
            )

        # Check for missing descriptions
        attrs_without_desc = [
            attr for attr in schema.attribute_types.values() if not attr.description
        ]
        ocs_without_desc = [
            oc for oc in schema.object_classes.values() if not oc.description
        ]

        if attrs_without_desc:
            recommendations.append(
                f"Add descriptions to {len(attrs_without_desc)} attribute types",
            )

        if ocs_without_desc:
            recommendations.append(
                f"Add descriptions to {len(ocs_without_desc)} object classes",
            )

        # Check for attributes without syntax
        attrs_without_syntax = [
            attr for attr in schema.attribute_types.values() if not attr.syntax
        ]

        if attrs_without_syntax:
            recommendations.append(
                f"Define syntax for {len(attrs_without_syntax)} attribute types",
            )

        # Check for naming consistency
        naming_issues = self._check_naming_consistency(schema)
        if naming_issues:
            recommendations.append(
                "Improve naming consistency for better maintainability",
            )

        # Check for unused attributes
        used_attributes = set()
        for oc in schema.object_classes.values():
            used_attributes.update(oc.must_attributes)
            used_attributes.update(oc.may_attributes)

        defined_attributes = {
            name for attr in schema.attribute_types.values() for name in attr.names
        }
        unused_attributes = defined_attributes - used_attributes

        if unused_attributes:
            recommendations.append(
                f"Review {len(unused_attributes)} unused attribute definitions",
            )

        return recommendations

    def _generate_statistics(self, schema: ParsedSchema) -> dict[str, Any]:
        """Generate detailed schema statistics."""
        statistics = {
            "total_attribute_types": len(schema.attribute_types),
            "total_object_classes": len(schema.object_classes),
            "total_syntax_definitions": len(schema.syntax_definitions),
            "total_matching_rules": len(schema.matching_rules),
        }

        # Attribute type statistics
        single_valued_attrs = sum(
            1 for attr in schema.attribute_types.values() if attr.single_value
        )
        multi_valued_attrs = len(schema.attribute_types) - single_valued_attrs

        statistics.update(
            {
                "single_valued_attributes": single_valued_attrs,
                "multi_valued_attributes": multi_valued_attrs,
                "obsolete_attributes": sum(
                    1 for attr in schema.attribute_types.values() if attr.obsolete
                ),
            },
        )

        # Object class statistics
        structural_ocs = sum(
            1 for oc in schema.object_classes.values() if oc.class_type == "STRUCTURAL"
        )
        auxiliary_ocs = sum(
            1 for oc in schema.object_classes.values() if oc.class_type == "AUXILIARY"
        )
        abstract_ocs = sum(
            1 for oc in schema.object_classes.values() if oc.class_type == "ABSTRACT"
        )

        statistics.update(
            {
                "structural_object_classes": structural_ocs,
                "auxiliary_object_classes": auxiliary_ocs,
                "abstract_object_classes": abstract_ocs,
                "obsolete_object_classes": sum(
                    1 for oc in schema.object_classes.values() if oc.obsolete
                ),
            },
        )

        # Complexity statistics
        max_inheritance_depth = max(
            (len(oc.superior_classes) for oc in schema.object_classes.values()),
            default=0,
        )

        total_must_attrs = sum(
            len(oc.must_attributes) for oc in schema.object_classes.values()
        )
        total_may_attrs = sum(
            len(oc.may_attributes) for oc in schema.object_classes.values()
        )

        statistics.update(
            {
                "max_inheritance_depth": max_inheritance_depth,
                "total_required_attributes": total_must_attrs,
                "total_optional_attributes": total_may_attrs,
            },
        )

        return statistics

    def _generate_warnings(self, schema: ParsedSchema) -> list[str]:
        """Generate analysis warnings."""
        warnings = []

        # Check for potential issues
        if len(schema.attribute_types) == 0:
            warnings.append("No attribute types defined in schema")

        if len(schema.object_classes) == 0:
            warnings.append("No object classes defined in schema")

        # Check for circular dependencies
        circular_deps = self._check_circular_dependencies(schema)
        if circular_deps:
            warnings.append(
                f"Potential circular dependencies detected: {', '.join(circular_deps)}",
            )

        return warnings

    def _is_well_named(self, name: str) -> bool:
        """Check if a name follows good naming conventions."""
        # Check for proper camelCase or kebab-case
        import re

        return bool(
            re.match(r"^[a-z][a-zA-Z0-9-]*$", name) and len(name) >= MIN_NAME_LENGTH,
        )

    def _check_naming_consistency(self, schema: ParsedSchema) -> list[str]:
        """Check for naming consistency issues."""
        issues = []

        # Check for mixed naming conventions
        camel_case_names = []
        kebab_case_names = []

        all_names = []
        for attr in schema.attribute_types.values():
            all_names.extend(attr.names)
        for oc in schema.object_classes.values():
            all_names.extend(oc.names)

        for name in all_names:
            if "-" in name:
                kebab_case_names.append(name)
            elif any(c.isupper() for c in name[1:]):
                camel_case_names.append(name)

        if camel_case_names and kebab_case_names:
            issues.append(
                "Mixed naming conventions detected (camelCase and kebab-case)",
            )

        return issues

    def _check_circular_dependencies(self, schema: ParsedSchema) -> list[str]:
        """Check for circular dependencies in schema."""
        circular_deps = []

        # Check object class inheritance
        visited = set()
        rec_stack = set()

        def has_cycle(oc_name: str) -> bool:
            if oc_name in rec_stack:
                return True
            if oc_name in visited:
                return False

            visited.add(oc_name)
            rec_stack.add(oc_name)

            # Find object class by name
            oc = None
            for obj_class in schema.object_classes.values():
                if oc_name.lower() in [n.lower() for n in obj_class.names]:
                    oc = obj_class
                    break

            if oc:
                for superior in oc.superior_classes:
                    if has_cycle(superior):
                        circular_deps.append(f"{oc_name} -> {superior}")
                        rec_stack.remove(oc_name)
                        return True

            rec_stack.remove(oc_name)
            return False

        for oc in schema.object_classes.values():
            for name in oc.names:
                if name not in visited:
                    has_cycle(name)

        return circular_deps

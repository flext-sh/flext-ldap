"""Schema Migrator - Generate migration plans and LDIF files.

This module provides capabilities to generate migration plans and LDIF files
for schema migrations between different LDAP servers.
"""

from __future__ import annotations

import logging
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ldap_core_shared.domain.results import LDAPOperationResult
from ldap_core_shared.schema.comparator import (
    DifferenceType,
    SchemaComparisonResult,
    SchemaDifference,
)

logger = logging.getLogger(__name__)


class MigrationPlan(BaseModel):
    """Schema migration plan with ordered steps."""

    model_config = ConfigDict(strict=True, extra="forbid")

    plan_name: str = Field(..., description="Migration plan name")
    source_schema: str = Field(..., description="Source schema identifier")
    target_schema: str = Field(..., description="Target schema identifier")
    migration_steps: list[str] = Field(
        default_factory=list,
        description="Ordered migration steps",
    )
    ldif_files: list[str] = Field(
        default_factory=list,
        description="Generated LDIF files",
    )
    warnings: list[str] = Field(default_factory=list, description="Migration warnings")
    estimated_duration: str = Field(
        default="",
        description="Estimated migration duration",
    )


class SchemaMigrator:
    """Generate schema migration plans and LDIF files."""

    def __init__(self) -> None:
        """Initialize schema migrator."""

    def generate_migration_plan(
        self,
        comparison_result: SchemaComparisonResult,
        output_dir: Path | str,
    ) -> LDAPOperationResult[MigrationPlan]:
        """Generate migration plan from schema comparison.

        Args:
            comparison_result: Results from schema comparison
            output_dir: Directory for output files

        Returns:
            Operation result with migration plan
        """
        try:
            output_dir = Path(output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)

            # Generate migration plan
            plan = self._create_migration_plan(comparison_result)

            # Generate LDIF files
            ldif_files = self._generate_ldif_files(comparison_result, output_dir)
            plan.ldif_files = ldif_files

            return LDAPOperationResult[MigrationPlan](
                success=True,
                data=plan,
                operation="generate_migration_plan",
                metadata={"output_dir": str(output_dir)},
            )

        except Exception as e:
            logger.exception("Failed to generate migration plan")
            return LDAPOperationResult[MigrationPlan](
                success=False,
                error_message=f"Plan generation failed: {e!s}",
                operation="generate_migration_plan",
            )

    def generate_ldif_for_additions(
        self,
        differences: list[SchemaDifference],
        output_path: Path | str,
    ) -> LDAPOperationResult[int]:
        """Generate LDIF file for schema additions.

        Args:
            differences: List of schema differences
            output_path: Output LDIF file path

        Returns:
            Operation result with number of additions
        """
        try:
            additions = [
                d for d in differences if d.difference_type == DifferenceType.ADDED
            ]

            if not additions:
                return LDAPOperationResult[int](
                    success=True,
                    data=0,
                    operation="generate_ldif_for_additions",
                    metadata={"message": "No additions found"},
                )

            # Group by element type
            attr_additions = [d for d in additions if d.element_type == "attributeType"]
            oc_additions = [d for d in additions if d.element_type == "objectClass"]

            # Generate LDIF content
            ldif_content = self._generate_addition_ldif_content(
                attr_additions,
                oc_additions,
            )

            # Write to file
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(ldif_content)

            return LDAPOperationResult[int](
                success=True,
                data=len(additions),
                operation="generate_ldif_for_additions",
                metadata={"output_path": str(output_path)},
            )

        except Exception as e:
            logger.exception(f"Failed to generate LDIF for additions: {output_path}")
            return LDAPOperationResult[int](
                success=False,
                error_message=f"LDIF generation failed: {e!s}",
                operation="generate_ldif_for_additions",
            )

    def _create_migration_plan(
        self,
        comparison_result: SchemaComparisonResult,
    ) -> MigrationPlan:
        """Create migration plan from comparison results."""
        plan = MigrationPlan(
            plan_name="Schema Migration Plan",
            source_schema="Source Schema",
            target_schema="Target Schema",
        )

        # Analyze differences and create steps
        additions = [
            d
            for d in comparison_result.differences
            if d.difference_type == DifferenceType.ADDED
        ]
        removals = [
            d
            for d in comparison_result.differences
            if d.difference_type == DifferenceType.REMOVED
        ]
        modifications = [
            d
            for d in comparison_result.differences
            if d.difference_type == DifferenceType.MODIFIED
        ]
        conflicts = [
            d
            for d in comparison_result.differences
            if d.difference_type == DifferenceType.CONFLICT
        ]

        # Create migration steps
        if additions:
            plan.migration_steps.append(f"1. Add {len(additions)} new schema elements")

        if modifications:
            plan.migration_steps.append(
                f"2. Modify {len(modifications)} existing schema elements",
            )
            plan.warnings.append("Schema modifications may require careful planning")

        if removals:
            plan.migration_steps.append(
                f"3. Remove {len(removals)} obsolete schema elements",
            )
            plan.warnings.append("Removing schema elements may affect existing data")

        if conflicts:
            plan.migration_steps.append(f"4. Resolve {len(conflicts)} schema conflicts")
            plan.warnings.append("Manual intervention required for schema conflicts")

        # Estimate duration
        total_changes = len(comparison_result.differences)
        if total_changes < 10:
            plan.estimated_duration = "< 1 hour"
        elif total_changes < 50:
            plan.estimated_duration = "1-4 hours"
        elif total_changes < 100:
            plan.estimated_duration = "4-8 hours"
        else:
            plan.estimated_duration = "> 8 hours"

        return plan

    def _generate_ldif_files(
        self,
        comparison_result: SchemaComparisonResult,
        output_dir: Path,
    ) -> list[str]:
        """Generate LDIF files for migration."""
        ldif_files = []

        # Generate additions LDIF
        additions = [
            d
            for d in comparison_result.differences
            if d.difference_type == DifferenceType.ADDED
        ]
        if additions:
            additions_file = output_dir / "01_schema_additions.ldif"
            content = self._generate_addition_ldif_content(
                [d for d in additions if d.element_type == "attributeType"],
                [d for d in additions if d.element_type == "objectClass"],
            )
            with open(additions_file, "w", encoding="utf-8") as f:
                f.write(content)
            ldif_files.append(str(additions_file))

        # Generate modifications LDIF
        modifications = [
            d
            for d in comparison_result.differences
            if d.difference_type == DifferenceType.MODIFIED
        ]
        if modifications:
            modifications_file = output_dir / "02_schema_modifications.ldif"
            content = self._generate_modification_ldif_content(modifications)
            with open(modifications_file, "w", encoding="utf-8") as f:
                f.write(content)
            ldif_files.append(str(modifications_file))

        # Generate removals LDIF
        removals = [
            d
            for d in comparison_result.differences
            if d.difference_type == DifferenceType.REMOVED
        ]
        if removals:
            removals_file = output_dir / "03_schema_removals.ldif"
            content = self._generate_removal_ldif_content(removals)
            with open(removals_file, "w", encoding="utf-8") as f:
                f.write(content)
            ldif_files.append(str(removals_file))

        return ldif_files

    def _generate_addition_ldif_content(
        self,
        attr_additions: list[SchemaDifference],
        oc_additions: list[SchemaDifference],
    ) -> str:
        """Generate LDIF content for schema additions."""
        lines = []

        # Header
        lines.append("# Schema Additions LDIF")
        lines.append("# Generated by ldap-core-shared Schema Migrator")
        lines.append("")
        lines.append("version: 1")
        lines.append("")

        # Add attribute types
        if attr_additions:
            lines.append("# Add Attribute Types")
            lines.append("dn: cn=schema")
            lines.append("changetype: modify")
            lines.append("add: attributeTypes")

            for diff in attr_additions:
                if diff.target_definition:
                    lines.append(f"attributeTypes: {diff.target_definition}")

            lines.append("-")
            lines.append("")

        # Add object classes
        if oc_additions:
            lines.append("# Add Object Classes")
            lines.append("dn: cn=schema")
            lines.append("changetype: modify")
            lines.append("add: objectClasses")

            for diff in oc_additions:
                if diff.target_definition:
                    lines.append(f"objectClasses: {diff.target_definition}")

            lines.append("-")
            lines.append("")

        return "\n".join(lines)

    def _generate_modification_ldif_content(
        self,
        modifications: list[SchemaDifference],
    ) -> str:
        """Generate LDIF content for schema modifications."""
        lines = []

        # Header
        lines.append("# Schema Modifications LDIF")
        lines.append("# WARNING: Review carefully before applying")
        lines.append("")
        lines.append("version: 1")
        lines.append("")

        # Group modifications by element type
        attr_mods = [d for d in modifications if d.element_type == "attributeType"]
        oc_mods = [d for d in modifications if d.element_type == "objectClass"]

        # Attribute type modifications
        if attr_mods:
            lines.append("# Modify Attribute Types")
            for diff in attr_mods:
                lines.append(f"# Element: {diff.element_name}")
                lines.append(f"# Change: {diff.description}")
                lines.append(f"# From: {diff.source_definition}")
                lines.append(f"# To: {diff.target_definition}")
                lines.append("#")
                lines.append("# Manual modification required")
                lines.append("")

        # Object class modifications
        if oc_mods:
            lines.append("# Modify Object Classes")
            for diff in oc_mods:
                lines.append(f"# Element: {diff.element_name}")
                lines.append(f"# Change: {diff.description}")
                lines.append(f"# From: {diff.source_definition}")
                lines.append(f"# To: {diff.target_definition}")
                lines.append("#")
                lines.append("# Manual modification required")
                lines.append("")

        return "\n".join(lines)

    def _generate_removal_ldif_content(self, removals: list[SchemaDifference]) -> str:
        """Generate LDIF content for schema removals."""
        lines = []

        # Header
        lines.append("# Schema Removals LDIF")
        lines.append("# WARNING: Ensure no data dependencies exist")
        lines.append("")
        lines.append("version: 1")
        lines.append("")

        # Group removals by element type
        attr_removals = [d for d in removals if d.element_type == "attributeType"]
        oc_removals = [d for d in removals if d.element_type == "objectClass"]

        # Remove object classes first (to avoid dependency issues)
        if oc_removals:
            lines.append("# Remove Object Classes")
            lines.append("dn: cn=schema")
            lines.append("changetype: modify")
            lines.append("delete: objectClasses")

            for diff in oc_removals:
                if diff.source_definition:
                    lines.append(f"objectClasses: {diff.source_definition}")

            lines.append("-")
            lines.append("")

        # Remove attribute types
        if attr_removals:
            lines.append("# Remove Attribute Types")
            lines.append("dn: cn=schema")
            lines.append("changetype: modify")
            lines.append("delete: attributeTypes")

            for diff in attr_removals:
                if diff.source_definition:
                    lines.append(f"attributeTypes: {diff.source_definition}")

            lines.append("-")
            lines.append("")

        return "\n".join(lines)

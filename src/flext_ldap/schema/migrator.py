"""Schema Migrator - Generate migration plans and LDIF files."""

from __future__ import annotations

import logging
from pathlib import Path

from flext_ldapants import DEFAULT_MAX_ITEMS
from flext_ldaparator import (
    DifferenceType,
    SchemaComparisonResult,
    SchemaDifference,
)
from pydantic import BaseModel, ConfigDict, Field

from flext_ldap.domain.results import LDAPOperationResult

# Constants for magic values
SMALL_CHANGE_THRESHOLD = 10  # Changes requiring < 1 hour
MEDIUM_CHANGE_THRESHOLD = 50  # Changes requiring 1-4 hours

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
            logger.exception("Failed to generate LDIF for additions: {output_path}")
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
        if total_changes < SMALL_CHANGE_THRESHOLD:
            plan.estimated_duration = "< 1 hour"
        elif total_changes < MEDIUM_CHANGE_THRESHOLD:
            plan.estimated_duration = "1-4 hours"
        elif total_changes < DEFAULT_MAX_ITEMS:
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
        lines.extend(
            (
                "# Schema Additions LDIF",
                "# Generated by ldap-core-shared Schema Migrator",
                "",
                "version: 1",
                "",
            ),
        )

        # Add attribute types
        if attr_additions:
            lines.extend(
                (
                    "# Add Attribute Types",
                    "dn: cn=schema",
                    "changetype: modify",
                    "add: attributeTypes",
                ),
            )

            lines.extend(
                f"attributeTypes: {diff.target_definition}"
                for diff in attr_additions
                if diff.target_definition
            )

            lines.extend(("-", ""))

        # Add object classes
        if oc_additions:
            lines.extend(
                (
                    "# Add Object Classes",
                    "dn: cn=schema",
                    "changetype: modify",
                    "add: objectClasses",
                ),
            )

            lines.extend(
                f"objectClasses: {diff.target_definition}"
                for diff in oc_additions
                if diff.target_definition
            )

            lines.extend(("-", ""))

        return "\n".join(lines)

    def _generate_modification_ldif_content(
        self,
        modifications: list[SchemaDifference],
    ) -> str:
        """Generate LDIF content for schema modifications."""
        lines = []

        # Header
        lines.extend(
            (
                "# Schema Modifications LDIF",
                "# WARNING: Review carefully before applying",
                "",
                "version: 1",
                "",
            ),
        )

        # Group modifications by element type
        attr_mods = [d for d in modifications if d.element_type == "attributeType"]
        oc_mods = [d for d in modifications if d.element_type == "objectClass"]

        # Attribute type modifications
        if attr_mods:
            lines.append("# Modify Attribute Types")
            for diff in attr_mods:
                lines.extend(
                    (
                        f"# Element: {diff.element_name}",
                        f"# Change: {diff.description}",
                        f"# From: {diff.source_definition}",
                        f"# To: {diff.target_definition}",
                        "#",
                        "# Manual modification required",
                        "",
                    ),
                )

        # Object class modifications
        if oc_mods:
            lines.append("# Modify Object Classes")
            for diff in oc_mods:
                lines.extend(
                    (
                        f"# Element: {diff.element_name}",
                        f"# Change: {diff.description}",
                        f"# From: {diff.source_definition}",
                        f"# To: {diff.target_definition}",
                        "#",
                        "# Manual modification required",
                        "",
                    ),
                )

        return "\n".join(lines)

    def _generate_removal_ldif_content(self, removals: list[SchemaDifference]) -> str:
        """Generate LDIF content for schema removals."""
        lines = []

        # Header
        lines.extend(
            (
                "# Schema Removals LDIF",
                "# WARNING: Ensure no data dependencies exist",
                "",
                "version: 1",
                "",
            ),
        )

        # Group removals by element type
        attr_removals = [d for d in removals if d.element_type == "attributeType"]
        oc_removals = [d for d in removals if d.element_type == "objectClass"]

        # Remove object classes first (to avoid dependency issues)
        if oc_removals:
            lines.extend(
                (
                    "# Remove Object Classes",
                    "dn: cn=schema",
                    "changetype: modify",
                    "delete: objectClasses",
                ),
            )

            lines.extend(
                f"objectClasses: {diff.source_definition}"
                for diff in oc_removals
                if diff.source_definition
            )

            lines.extend(("-", ""))

        # Remove attribute types
        if attr_removals:
            lines.extend(
                (
                    "# Remove Attribute Types",
                    "dn: cn=schema",
                    "changetype: modify",
                    "delete: attributeTypes",
                ),
            )

            lines.extend(
                f"attributeTypes: {diff.source_definition}"
                for diff in attr_removals
                if diff.source_definition
            )

            lines.extend(("-", ""))

        return "\n".join(lines)

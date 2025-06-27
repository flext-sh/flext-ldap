#!/usr/bin/env python3
"""CLAUDE.md Documentation Validation System.

Implements the automated validation protocols specified in CLAUDE.md for
maintaining documentation hierarchy integrity and compliance.

DESIGN PATTERN: DOCUMENTATION VALIDATION (CLAUDE.md Protocol)
============================================================

This script validates:
- Documentation hierarchy integrity
- Cross-reference validation
- Freshness monitoring
- Pattern compliance
- Memory optimization adherence

References:
- /home/marlonsc/CLAUDE.md → Universal principles
- ../CLAUDE.md → PyAuto workspace patterns
- ./CLAUDE.local.md → Project-specific issues
"""

import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path


@dataclass
class ValidationResult:
    """Validation result following CLAUDE.md Result pattern."""

    success: bool
    message: str
    details: dict
    timestamp: str
    execution_time_ms: float


@dataclass
class DocumentationHierarchy:
    """Documentation hierarchy structure following CLAUDE.md patterns."""

    global_claude: Path | None
    global_local: Path | None
    workspace_claude: Path | None
    workspace_local: Path | None
    project_local: Path | None


class CLAUDEDocumentationValidator:
    """CLAUDE.md Documentation Validation System.

    Implements systematic validation protocols for maintaining documentation
    hierarchy integrity as specified in CLAUDE.md universal principles.

    VALIDATION CATEGORIES:
    - Hierarchy Structure Validation
    - Cross-Reference Integrity
    - Freshness Monitoring
    - Pattern Compliance
    - Memory Optimization
    """

    def __init__(self, project_root: Path) -> None:
        """Initialize validator with project root."""
        self.project_root = Path(project_root)
        self.workspace_root = self.project_root.parent
        self.global_root = Path("/home/marlonsc")

        # Initialize hierarchy discovery
        self.hierarchy = self._discover_hierarchy()

        # Validation results storage
        self.validation_results: list[ValidationResult] = []

    def _discover_hierarchy(self) -> DocumentationHierarchy:
        """Discover documentation hierarchy following CLAUDE.md structure."""
        return DocumentationHierarchy(
            global_claude=self.global_root / "CLAUDE.md",
            global_local=self.global_root / "CLAUDE.local.md",
            workspace_claude=self.workspace_root / "CLAUDE.md",
            workspace_local=self.workspace_root / "CLAUDE.local.md",
            project_local=self.project_root / "CLAUDE.local.md",
        )

    def validate_hierarchy_structure(self) -> ValidationResult:
        """Validate documentation hierarchy structure.

        CLAUDE.md REQUIREMENT: Documentation hierarchy must be properly structured
        with correct reference chains and authority levels.
        """
        start_time = datetime.now()
        issues = []

        # Validate file existence
        required_files = [
            (self.hierarchy.global_claude, "Global CLAUDE.md"),
            (self.hierarchy.workspace_claude, "Workspace CLAUDE.md"),
            (self.hierarchy.project_local, "Project CLAUDE.local.md"),
        ]

        for file_path, description in required_files:
            if not file_path.exists():
                issues.append(f"Missing required file: {description} at {file_path}")

        # Validate hierarchy references
        if self.hierarchy.project_local.exists():
            content = self.hierarchy.project_local.read_text()
            expected_refs = [
                "/home/marlonsc/CLAUDE.md",
                "../CLAUDE.md",
                "/home/marlonsc/CLAUDE.local.md",
            ]

            issues.extend(
                f"Missing reference to {ref} in project CLAUDE.local.md"
                for ref in expected_refs
                if ref not in content
            )

        execution_time = (datetime.now() - start_time).total_seconds() * 1000

        return ValidationResult(
            success=len(issues) == 0,
            message=f"Hierarchy validation {'passed' if len(issues) == 0 else 'failed'}",
            details={"issues": issues, "files_checked": len(required_files)},
            timestamp=datetime.now().isoformat(),
            execution_time_ms=execution_time,
        )

    def validate_cross_references(self) -> ValidationResult:
        """Validate cross-reference integrity.

        CLAUDE.md REQUIREMENT: All documentation cross-references must point
        to existing files and maintain proper hierarchy relationships.
        """
        start_time = datetime.now()
        broken_refs = []

        # Extract and validate references from all documentation files
        for file_path in [
            f
            for f in [
                self.hierarchy.global_claude,
                self.hierarchy.global_local,
                self.hierarchy.workspace_claude,
                self.hierarchy.workspace_local,
                self.hierarchy.project_local,
            ]
            if f and f.exists()
        ]:
            content = file_path.read_text()

            # Find reference patterns
            ref_patterns = [
                r"Reference.*?→\s*([^\n]+)",
                r"See\s+`([^`]+)`",
                r"\[([^\]]+)\]\(([^)]+)\)",
            ]

            for pattern in ref_patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    ref_path = match if isinstance(match, str) else match[1]
                    if ref_path.startswith(("/", "./", "../")):
                        # Resolve relative path
                        if ref_path.startswith("/"):
                            abs_path = Path(ref_path)
                        else:
                            abs_path = (file_path.parent / ref_path).resolve()

                        if not abs_path.exists():
                            broken_refs.append(
                                {
                                    "file": str(file_path),
                                    "reference": ref_path,
                                    "resolved_path": str(abs_path),
                                }
                            )

        execution_time = (datetime.now() - start_time).total_seconds() * 1000

        return ValidationResult(
            success=len(broken_refs) == 0,
            message=f"Cross-reference validation {'passed' if len(broken_refs) == 0 else 'failed'}",
            details={
                "broken_references": broken_refs,
                "total_checked": len(broken_refs),
            },
            timestamp=datetime.now().isoformat(),
            execution_time_ms=execution_time,
        )

    def validate_freshness(self) -> ValidationResult:
        """Validate documentation freshness.

        CLAUDE.md REQUIREMENT: Documentation must be kept current with
        automated freshness monitoring and update tracking.
        """
        start_time = datetime.now()
        stale_files = []

        # Check for stale documentation (>7 days without update)
        cutoff_date = datetime.now() - timedelta(days=7)

        for file_path in [
            f
            for f in [
                self.hierarchy.workspace_claude,
                self.hierarchy.workspace_local,
                self.hierarchy.project_local,
            ]
            if f and f.exists()
        ]:
            # Get file modification time
            mod_time = datetime.fromtimestamp(file_path.stat().st_mtime)

            if mod_time < cutoff_date:
                # Check if file has "Last Updated" field
                content = file_path.read_text()
                last_updated_match = re.search(
                    r"Last Updated.*?(\d{4}-\d{2}-\d{2})", content
                )

                if last_updated_match:
                    last_updated = datetime.strptime(
                        last_updated_match.group(1), "%Y-%m-%d"
                    )
                    if last_updated < cutoff_date:
                        stale_files.append(
                            {
                                "file": str(file_path),
                                "last_modified": mod_time.isoformat(),
                                "last_updated_field": last_updated.isoformat(),
                                "days_stale": (datetime.now() - last_updated).days,
                            }
                        )
                else:
                    stale_files.append(
                        {
                            "file": str(file_path),
                            "last_modified": mod_time.isoformat(),
                            "last_updated_field": None,
                            "days_stale": (datetime.now() - mod_time).days,
                        }
                    )

        execution_time = (datetime.now() - start_time).total_seconds() * 1000

        return ValidationResult(
            success=len(stale_files) == 0,
            message=f"Freshness validation {'passed' if len(stale_files) == 0 else 'failed'}",
            details={"stale_files": stale_files, "cutoff_days": 7},
            timestamp=datetime.now().isoformat(),
            execution_time_ms=execution_time,
        )

    def validate_pattern_compliance(self) -> ValidationResult:
        """Validate CLAUDE.md pattern compliance.

        CLAUDE.md REQUIREMENT: All documentation must follow established
        patterns for structure, content, and maintenance protocols.
        """
        start_time = datetime.now()
        violations = []

        # Check project CLAUDE.local.md for required sections
        if self.hierarchy.project_local.exists():
            content = self.hierarchy.project_local.read_text()

            required_sections = [
                "PROJECT-SPECIFIC CONFIGURATION",
                "Virtual Environment Usage",
                "Agent Coordination",
                ".env.*SECURITY.*REQUIREMENTS",
                "MANDATORY.*CLI Usage",
            ]

            violations.extend(
                {
                    "file": str(self.hierarchy.project_local),
                    "violation": f"Missing required section: {section}",
                    "severity": "high",
                }
                for section in required_sections
                if not re.search(section, content, re.IGNORECASE)
            )

        # Check for proper hierarchy references
        if self.hierarchy.project_local.exists():
            content = self.hierarchy.project_local.read_text()

            if not re.search(r"Reference.*CLAUDE\.md.*Universal principles", content):
                violations.append(
                    {
                        "file": str(self.hierarchy.project_local),
                        "violation": "Missing universal principles reference",
                        "severity": "medium",
                    }
                )

        execution_time = (datetime.now() - start_time).total_seconds() * 1000

        return ValidationResult(
            success=len(violations) == 0,
            message=f"Pattern compliance {'passed' if len(violations) == 0 else 'failed'}",
            details={"violations": violations, "patterns_checked": 5},
            timestamp=datetime.now().isoformat(),
            execution_time_ms=execution_time,
        )

    def validate_memory_optimization(self) -> ValidationResult:
        """Validate memory optimization protocols.

        CLAUDE.md REQUIREMENT: Documentation must implement memory optimization
        strategies for context retention and conflict resolution.
        """
        start_time = datetime.now()
        memory_issues = []

        # Check for .token files and coordination
        token_files = list(self.project_root.glob("*.token")) + list(
            self.project_root.glob(".token")
        )

        if not token_files:
            memory_issues.append(
                {
                    "issue": "No .token files found for agent coordination",
                    "severity": "medium",
                    "location": str(self.project_root),
                }
            )

        # Check for memory optimization files
        memory_files = [
            ".context_memory",
            ".pattern_memory",
            ".failure_memory",
            ".resolution_memory",
        ]

        memory_issues.extend(
            {
                "issue": f"Missing memory optimization file: {memory_file}",
                "severity": "low",
                "location": str(self.project_root / memory_file),
            }
            for memory_file in memory_files
            if not (self.project_root / memory_file).exists()
        )

        execution_time = (datetime.now() - start_time).total_seconds() * 1000

        return ValidationResult(
            success=len(memory_issues) == 0,
            message=f"Memory optimization {'passed' if len(memory_issues) == 0 else 'failed'}",
            details={
                "memory_issues": memory_issues,
                "token_files_found": len(token_files),
            },
            timestamp=datetime.now().isoformat(),
            execution_time_ms=execution_time,
        )

    def run_comprehensive_validation(self) -> dict:
        """Run comprehensive validation suite.

        CLAUDE.md REQUIREMENT: Systematic validation of all documentation
        standards and protocols.
        """
        # Run all validation categories
        validations = [
            ("Hierarchy Structure", self.validate_hierarchy_structure),
            ("Cross-References", self.validate_cross_references),
            ("Freshness Monitoring", self.validate_freshness),
            ("Pattern Compliance", self.validate_pattern_compliance),
            ("Memory Optimization", self.validate_memory_optimization),
        ]

        results = {}
        total_success = True

        for name, validator in validations:
            result = validator()
            results[name] = asdict(result)

            if result.success:
                pass
            else:
                total_success = False

                # Print detailed issues
                if result.details:
                    for value in result.details.values():
                        if isinstance(value, list) and value:
                            for item in value[:3]:  # Show first 3 issues
                                if isinstance(item, dict):
                                    pass

        if total_success:
            pass

        return {
            "overall_success": total_success,
            "validation_results": results,
            "summary": {
                "total_validations": len(validations),
                "successful": sum(1 for r in results.values() if r["success"]),
                "failed": sum(1 for r in results.values() if not r["success"]),
                "timestamp": datetime.now().isoformat(),
            },
        }


def main() -> None:
    """Main validation execution following CLAUDE.md protocols."""
    project_root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()

    # Initialize validator
    validator = CLAUDEDocumentationValidator(project_root)

    # Run comprehensive validation
    results = validator.run_comprehensive_validation()

    # Save results for monitoring
    results_file = project_root / "validation_results.json"
    with open(results_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    # Exit with appropriate code
    sys.exit(0 if results["overall_success"] else 1)


if __name__ == "__main__":
    main()

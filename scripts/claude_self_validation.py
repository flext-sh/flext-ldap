#!/usr/bin/env python3
"""CLAUDE.md Self-Validation System.

Implements the complete self-validation system specified in CLAUDE.md for
systematic validation of project standards and continuous improvement.

DESIGN PATTERN: SELF-VALIDATION SYSTEM (CLAUDE.md Protocol)
===========================================================

This script implements the ENHANCED SELF-VALIDATION SYSTEM from CLAUDE.md:
- Documentation hierarchy validation
- Pattern recognition and memory
- Failure prevention protocols
- Conflict resolution tracking
- Agent coordination validation
- Performance characteristics monitoring

References:
- /home/marlonsc/CLAUDE.md → Universal principles (ENHANCED SELF-VALIDATION SYSTEM)
- ../CLAUDE.md → PyAuto workspace patterns
- ./CLAUDE.local.md → Project-specific issues
"""

import json
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# Constants for pattern analysis effectiveness thresholds
PATTERN_EFFECTIVENESS_HIGH_THRESHOLD = 5    # Unique patterns for HIGH effectiveness
PATTERN_EFFECTIVENESS_MEDIUM_THRESHOLD = 2  # Unique patterns for MEDIUM effectiveness

# Constants for parsing pattern memory entries
PATTERN_PARTS_MINIMUM = 4               # Minimum parts for valid pattern entry
SOLUTION_PARTS_MINIMUM = 3              # Minimum parts for solution entry
FAILURE_PARTS_MINIMUM = 2               # Minimum parts for failure entry
PREVENTION_PARTS_MINIMUM = 2            # Minimum parts for prevention entry

# Constants for failure analysis thresholds
FAILURE_EFFECTIVENESS_HIGH_THRESHOLD = 3    # Failures for HIGH effectiveness rating
FAILURE_EFFECTIVENESS_MEDIUM_THRESHOLD = 1  # Failures for MEDIUM effectiveness rating

# Constants for overall health assessment
CRITICAL_SYSTEMS_GOOD_THRESHOLD = 2     # Minimum critical systems for GOOD health

# Import our documentation validator
from claude_documentation_validator import CLAUDEDocumentationValidator


@dataclass
class SelfValidationReport:
    """Complete self-validation report following CLAUDE.md patterns."""
    timestamp: str
    project_name: str
    workspace: str
    validation_categories: dict
    memory_analysis: dict
    pattern_recognition: dict
    failure_prevention: dict
    coordination_status: dict
    overall_health: str
    recommendations: list[str]


class CLAUDESelfValidationSystem:
    """CLAUDE.md Self-Validation System.

    Implements the comprehensive self-validation protocols specified in
    CLAUDE.md for maintaining project health and continuous improvement.

    VALIDATION CATEGORIES (from CLAUDE.md):
    - Global Documentation Hierarchy
    - Cross-workspace Pattern Analysis
    - Project-specific Compliance
    - Memory Optimization Effectiveness
    - Agent Coordination Protocols
    - Pattern Recognition Analysis
    - Failure Prevention Systems
    """

    def __init__(self, project_root: Path) -> None:
        """Initialize self-validation system."""
        self.project_root = Path(project_root)
        self.workspace_root = self.project_root.parent
        self.global_root = Path("/home/marlonsc")

        # Initialize documentation validator
        self.doc_validator = CLAUDEDocumentationValidator(project_root)

        # Initialize validation tracking
        self.validation_results = {}
        self.recommendations = []

    def validate_global_methodology(self) -> dict:
        """Validate global methodology compliance.

        CLAUDE.md REQUIREMENT: ENHANCED SELF-VALIDATION SYSTEM
        Weekly execution with strict reporting and cross-validation.
        """
        issues = []

        # Check global CLAUDE.md exists and is authoritative
        global_claude = self.global_root / "CLAUDE.md"
        if not global_claude.exists():
            issues.append("CRITICAL: Global CLAUDE.md missing")
        else:
            content = global_claude.read_text()
            # Check for key methodology sections
            key_sections = [
                "ZERO TOLERANCE APPROACH",
                "INVESTIGATE DEEP - VERIFY EVERYTHING",
                "FIX REAL - NO BAND-AID SOLUTIONS",
                "IMPLEMENT TRUTH - REALITY OVER DOCUMENTATION",
                "ENHANCED SELF-VALIDATION SYSTEM",
            ]

            issues.extend(f"Missing key methodology section: {section}" for section in key_sections if section not in content)

        # Check workspace methodology compliance
        workspace_claude = self.workspace_root / "CLAUDE.md"
        if not workspace_claude.exists():
            issues.append("CRITICAL: Workspace CLAUDE.md missing")
        else:
            content = workspace_claude.read_text()
            if "/home/marlonsc/CLAUDE.md" not in content:
                issues.append("Workspace CLAUDE.md missing global reference")

        success = len(issues) == 0

        if issues:
            for _issue in issues[:3]:  # Show first 3 issues
                pass

        return {
            "success": success,
            "issues": issues,
            "files_checked": 2,
        }

    def analyze_memory_optimization(self) -> dict:
        """Analyze memory optimization effectiveness.

        CLAUDE.md REQUIREMENT: CONTEXT RETENTION STRATEGIES and
        PATTERN RECOGNITION MEMORY systems.
        """
        memory_files = {
            ".context_memory": "Context retention across sessions",
            ".pattern_memory": "Pattern recognition and frequency tracking",
            ".failure_memory": "Failure prevention documentation",
            ".resolution_memory": "Conflict resolution tracking",
        }

        memory_analysis = {}

        for filename, description in memory_files.items():
            filepath = self.project_root / filename

            if filepath.exists():
                content = filepath.read_text()
                lines = content.strip().split("\n")

                memory_analysis[filename] = {
                    "exists": True,
                    "lines_count": len(lines),
                    "last_modified": datetime.fromtimestamp(filepath.stat().st_mtime).isoformat(),
                    "description": description,
                    "status": "ACTIVE" if lines else "EMPTY",
                }

            else:
                memory_analysis[filename] = {
                    "exists": False,
                    "status": "MISSING",
                    "description": description,
                }

        # Analyze pattern recognition effectiveness
        pattern_file = self.project_root / ".pattern_memory"
        if pattern_file.exists():
            patterns = [line for line in pattern_file.read_text().split("\n") if line.startswith("PATTERN_")]
            unique_patterns = len({line.split("_")[1] for line in patterns if "_" in line})
            memory_analysis["pattern_analysis"] = {
                "total_patterns": len(patterns),
                "unique_patterns": unique_patterns,
                "effectiveness": "HIGH" if unique_patterns > PATTERN_EFFECTIVENESS_HIGH_THRESHOLD else "MEDIUM" if unique_patterns > PATTERN_EFFECTIVENESS_MEDIUM_THRESHOLD else "LOW",
            }

        return memory_analysis

    def validate_agent_coordination(self) -> dict:
        """Validate agent coordination protocols.

        CLAUDE.md REQUIREMENT: ENHANCED MULTI-AGENT COORDINATION PROTOCOL
        with conflict prevention and completion verification.
        """
        coordination_analysis = {}

        # Check .token file
        token_file = self.project_root / ".token"
        if token_file.exists():
            content = token_file.read_text()
            lines = content.strip().split("\n")

            # Analyze coordination entries
            agent_entries = [line for line in lines if line.startswith("AGENT_")]
            objective_entries = [line for line in lines if "OBJECTIVE" in line]
            completion_entries = [line for line in lines if "COMPLETED" in line]

            coordination_analysis[".token"] = {
                "exists": True,
                "total_entries": len(lines),
                "agent_entries": len(agent_entries),
                "objective_entries": len(objective_entries),
                "completion_entries": len(completion_entries),
                "coordination_health": "GOOD" if agent_entries and completion_entries else "NEEDS_IMPROVEMENT",
            }

        else:
            coordination_analysis[".token"] = {
                "exists": False,
                "coordination_health": "MISSING",
            }

        # Check workspace coordination
        workspace_token = self.workspace_root / ".token"
        if workspace_token.exists():
            coordination_analysis["workspace_coordination"] = {"exists": True}
        else:
            coordination_analysis["workspace_coordination"] = {"exists": False}

        return coordination_analysis

    def analyze_pattern_recognition(self) -> dict:
        """Analyze pattern recognition effectiveness.

        CLAUDE.md REQUIREMENT: PATTERN RECOGNITION MEMORY with
        frequency tracking and solution documentation.
        """
        pattern_analysis = {}

        # Analyze documented patterns
        pattern_file = self.project_root / ".pattern_memory"
        if pattern_file.exists():
            content = pattern_file.read_text()
            patterns = {}

            for line in content.split("\n"):
                if line.startswith("PATTERN_") and "_FREQUENCY_" in line:
                    parts = line.split("_")
                    if len(parts) >= PATTERN_PARTS_MINIMUM:
                        pattern_name = parts[1]
                        frequency = line.split("_FREQUENCY_")[-1] if "_FREQUENCY_" in line else "0"

                        if pattern_name not in patterns:
                            patterns[pattern_name] = {
                                "frequency": int(frequency) if frequency.isdigit() else 0,
                                "solutions": [],
                            }

            # Find solutions for patterns
            for line in content.split("\n"):
                if "_SOLUTION_" in line:
                    parts = line.split("_")
                    if len(parts) >= SOLUTION_PARTS_MINIMUM:
                        pattern_name = parts[1]
                        solution = line.split("_SOLUTION_")[-1] if "_SOLUTION_" in line else ""

                        if pattern_name in patterns:
                            patterns[pattern_name]["solutions"].append(solution)

            pattern_analysis = {
                "total_patterns": len(patterns),
                "patterns": patterns,
                "high_frequency_patterns": [p for p, data in patterns.items() if data["frequency"] > 1],
                "effectiveness": "HIGH" if len(patterns) > PATTERN_EFFECTIVENESS_HIGH_THRESHOLD else "MEDIUM" if len(patterns) > PATTERN_EFFECTIVENESS_MEDIUM_THRESHOLD else "LOW",
            }

            for _pattern, _data in list(patterns.items())[:3]:  # Show first 3
                pass

        else:
            pattern_analysis = {
                "total_patterns": 0,
                "effectiveness": "NONE",
                "status": "NO_PATTERN_MEMORY",
            }

        return pattern_analysis

    def validate_failure_prevention(self) -> dict:
        """Validate failure prevention systems.

        CLAUDE.md REQUIREMENT: FAILURE PREVENTION MEMORY with
        context documentation and prevention methods.
        """
        failure_analysis = {}

        # Analyze failure prevention documentation
        failure_file = self.project_root / ".failure_memory"
        if failure_file.exists():
            content = failure_file.read_text()
            failures = {}

            for line in content.split("\n"):
                if line.startswith("FAILURE_") and "_CONTEXT_" in line:
                    parts = line.split("_CONTEXT_")
                    if len(parts) >= FAILURE_PARTS_MINIMUM:
                        failure_type = parts[0].replace("FAILURE_", "")
                        context = parts[1]

                        if failure_type not in failures:
                            failures[failure_type] = {
                                "context": context,
                                "prevention": None,
                                "last_seen": None,
                            }

            # Find prevention methods
            for line in content.split("\n"):
                if "_PREVENTION_" in line:
                    parts = line.split("_PREVENTION_")
                    if len(parts) >= PREVENTION_PARTS_MINIMUM:
                        failure_type = parts[0].replace("FAILURE_", "")
                        prevention = parts[1]

                        if failure_type in failures:
                            failures[failure_type]["prevention"] = prevention

            failure_analysis = {
                "total_failures_documented": len(failures),
                "failures": failures,
                "prevention_coverage": len([f for f in failures.values() if f["prevention"]]) / len(failures) if failures else 0,
                "effectiveness": "HIGH" if len(failures) > FAILURE_EFFECTIVENESS_HIGH_THRESHOLD else "MEDIUM" if len(failures) > FAILURE_EFFECTIVENESS_MEDIUM_THRESHOLD else "LOW",
            }

            for failure_type, data in list(failures.items())[:3]:  # Show first 3
                "✅" if data["prevention"] else "❌"

        else:
            failure_analysis = {
                "total_failures_documented": 0,
                "effectiveness": "NONE",
                "status": "NO_FAILURE_MEMORY",
            }

        return failure_analysis

    def run_comprehensive_self_validation(self) -> SelfValidationReport:
        """Run comprehensive self-validation suite.

        CLAUDE.md REQUIREMENT: Complete self-validation with all systems
        and protocols as specified in ENHANCED SELF-VALIDATION SYSTEM.
        """
        # Run documentation validation first
        doc_results = self.doc_validator.run_comprehensive_validation()

        # Run methodology validation
        methodology_results = self.validate_global_methodology()

        # Run memory optimization analysis
        memory_results = self.analyze_memory_optimization()

        # Run agent coordination validation
        coordination_results = self.validate_agent_coordination()

        # Run pattern recognition analysis
        pattern_results = self.analyze_pattern_recognition()

        # Run failure prevention validation
        failure_results = self.validate_failure_prevention()

        # Determine overall health
        critical_systems = [
            doc_results["overall_success"],
            methodology_results["success"],
            coordination_results.get(".token", {}).get("exists", False),
        ]

        if all(critical_systems):
            overall_health = "EXCELLENT"
        elif sum(critical_systems) >= CRITICAL_SYSTEMS_GOOD_THRESHOLD:
            overall_health = "GOOD"
        else:
            overall_health = "NEEDS_IMPROVEMENT"

        # Generate recommendations
        recommendations = []

        if not doc_results["overall_success"]:
            recommendations.append("Fix documentation validation issues")

        if not methodology_results["success"]:
            recommendations.append("Address global methodology compliance issues")

        if memory_results.get(".context_memory", {}).get("status") == "MISSING":
            recommendations.append("Implement context memory system")

        if coordination_results.get(".token", {}).get("coordination_health") != "GOOD":
            recommendations.append("Improve agent coordination protocols")

        if pattern_results.get("effectiveness", "NONE") == "LOW":
            recommendations.append("Enhance pattern recognition documentation")

        if failure_results.get("effectiveness", "NONE") == "LOW":
            recommendations.append("Improve failure prevention documentation")

        # Create comprehensive report
        report = SelfValidationReport(
            timestamp=datetime.now().isoformat(),
            project_name=self.project_root.name,
            workspace=self.workspace_root.name,
            validation_categories={
                "documentation": doc_results,
                "methodology": methodology_results,
            },
            memory_analysis=memory_results,
            pattern_recognition=pattern_results,
            failure_prevention=failure_results,
            coordination_status=coordination_results,
            overall_health=overall_health,
            recommendations=recommendations,
        )

        # Print summary

        if recommendations:
            for _i, _rec in enumerate(recommendations[:5], 1):  # Show first 5
                pass

        return report


def main() -> None:
    """Main self-validation execution following CLAUDE.md protocols."""
    project_root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()

    # Initialize self-validation system
    validator = CLAUDESelfValidationSystem(project_root)

    # Run comprehensive validation
    report = validator.run_comprehensive_self_validation()

    # Save comprehensive report
    report_file = project_root / "self_validation_report.json"
    with open(report_file, "w", encoding="utf-8") as f:
        # Convert dataclass to dict for JSON serialization
        report_dict = {
            "timestamp": report.timestamp,
            "project_name": report.project_name,
            "workspace": report.workspace,
            "validation_categories": report.validation_categories,
            "memory_analysis": report.memory_analysis,
            "pattern_recognition": report.pattern_recognition,
            "failure_prevention": report.failure_prevention,
            "coordination_status": report.coordination_status,
            "overall_health": report.overall_health,
            "recommendations": report.recommendations,
        }
        json.dump(report_dict, f, indent=2)

    # Update memory systems
    if report.overall_health in {"EXCELLENT", "GOOD"}:
        # Log successful validation to context memory
        context_file = project_root / ".context_memory"
        if context_file.exists():
            with open(context_file, "a", encoding="utf-8") as f:
                f.write(f"\nSELF_VALIDATION_SUCCESS_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

    # Exit with appropriate code
    success_code = 0 if report.overall_health in {"EXCELLENT", "GOOD"} else 1
    sys.exit(success_code)


if __name__ == "__main__":
    main()

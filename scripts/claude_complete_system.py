#!/usr/bin/env python3
"""CLAUDE.md Complete System Integration.

Master script that runs all CLAUDE.md protocols and systems for
comprehensive project validation and maintenance.

DESIGN PATTERN: COMPLETE CLAUDE.md SYSTEM INTEGRATION
====================================================

This script orchestrates all CLAUDE.md systems:
- Documentation validation
- Self-validation system
- Freshness monitoring
- Pattern recognition
- Failure prevention
- Memory optimization
- Agent coordination

References:
- /home/marlonsc/CLAUDE.md → Universal principles (ALL SYSTEMS)
- ../CLAUDE.md → PyAuto workspace patterns
- ./internal.invalid.md → Project-specific issues
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


class CLAUDECompleteSystem:
    """CLAUDE.md Complete System Integration.

    Master orchestrator for all CLAUDE.md protocols and systems
    ensuring comprehensive project health and compliance.
    """

    def __init__(self, project_root: Path) -> None:
        """Initialize complete CLAUDE.md system."""
        self.project_root = Path(project_root)
        self.scripts_dir = self.project_root / "scripts"

        # System components
        self.systems = {
            "documentation": "claude_documentation_validator.py",
            "self_validation": "claude_self_validation.py",
            "freshness": "claude_freshness_monitor.py",
        }

        self.results = {}

    def run_documentation_validation(self) -> dict:
        """Run documentation validation system."""
        script_path = self.scripts_dir / self.systems["documentation"]
        if not script_path.exists():
            return {"success": False, "error": "Documentation validator script not found"}

        try:
            result = subprocess.run(
                [sys.executable, str(script_path)],
                check=False, cwd=self.project_root,
                capture_output=True,
                text=True,
            )

            # Load results if available
            results_file = self.project_root / "validation_results.json"
            if results_file.exists():
                with open(results_file, encoding="utf-8") as f:
                    validation_results = json.load(f)
            else:
                validation_results = {"overall_success": result.returncode == 0}

            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr or None,
                "results": validation_results,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def run_self_validation(self) -> dict:
        """Run self-validation system."""
        script_path = self.scripts_dir / self.systems["self_validation"]
        if not script_path.exists():
            return {"success": False, "error": "Self-validation script not found"}

        try:
            result = subprocess.run(
                [sys.executable, str(script_path)],
                check=False, cwd=self.project_root,
                capture_output=True,
                text=True,
            )

            # Load results if available
            results_file = self.project_root / "self_validation_report.json"
            if results_file.exists():
                with open(results_file, encoding="utf-8") as f:
                    self_validation_results = json.load(f)
            else:
                self_validation_results = {"overall_health": "UNKNOWN"}

            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr or None,
                "results": self_validation_results,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def run_freshness_monitoring(self) -> dict:
        """Run freshness monitoring system."""
        script_path = self.scripts_dir / self.systems["freshness"]
        if not script_path.exists():
            return {"success": False, "error": "Freshness monitor script not found"}

        try:
            result = subprocess.run(
                [sys.executable, str(script_path)],
                check=False, cwd=self.project_root,
                capture_output=True,
                text=True,
            )

            # Load results if available
            results_file = self.project_root / "freshness_report.json"
            if results_file.exists():
                with open(results_file, encoding="utf-8") as f:
                    freshness_results = json.load(f)
            else:
                freshness_results = {"overall_status": "UNKNOWN"}

            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr or None,
                "results": freshness_results,
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def validate_system_integrity(self) -> dict:
        """Validate that all CLAUDE.md systems are properly installed."""
        integrity_results = {
            "scripts_available": {},
            "memory_files": {},
            "coordination_files": {},
            "overall_integrity": True,
        }

        # Check script availability
        for system_name, script_name in self.systems.items():
            script_path = self.scripts_dir / script_name
            available = script_path.exists()
            integrity_results["scripts_available"][system_name] = {
                "available": available,
                "path": str(script_path),
            }
            if not available:
                integrity_results["overall_integrity"] = False

        # Check memory files
        memory_files = [".context_memory", ".pattern_memory", ".failure_memory", ".resolution_memory"]
        for memory_file in memory_files:
            file_path = self.project_root / memory_file
            exists = file_path.exists()
            integrity_results["memory_files"][memory_file] = {
                "exists": exists,
                "path": str(file_path),
            }
            if not exists:
                pass

        # Check coordination files
        coordination_files = [".token"]
        for coord_file in coordination_files:
            file_path = self.project_root / coord_file
            exists = file_path.exists()
            integrity_results["coordination_files"][coord_file] = {
                "exists": exists,
                "path": str(file_path),
            }
            if not exists:
                pass

        return integrity_results

    def generate_comprehensive_report(self) -> dict:
        """Generate comprehensive system report."""
        overall_health = "EXCELLENT"
        critical_issues = []
        recommendations = []

        # Analyze documentation validation
        if "documentation" in self.results:
            doc_result = self.results["documentation"]
            if not doc_result.get("success", False):
                overall_health = "NEEDS_IMPROVEMENT"
                critical_issues.append("Documentation validation failed")
                recommendations.append("Fix documentation validation issues")

        # Analyze self-validation
        if "self_validation" in self.results:
            self_val_result = self.results["self_validation"]
            health = self_val_result.get("results", {}).get("overall_health", "UNKNOWN")
            if health not in {"EXCELLENT", "GOOD"}:
                overall_health = "NEEDS_IMPROVEMENT"
                critical_issues.append(f"Self-validation health: {health}")
                recommendations.append("Address self-validation issues")

        # Analyze freshness monitoring
        if "freshness" in self.results:
            fresh_result = self.results["freshness"]
            status = fresh_result.get("results", {}).get("overall_status", "UNKNOWN")
            if status in {"CRITICAL", "NEEDS_UPDATE"}:
                if overall_health == "EXCELLENT":
                    overall_health = "GOOD"
                critical_issues.append(f"Documentation freshness: {status}")
                recommendations.append("Update stale documentation")

        # System integrity check
        if "integrity" in self.results:
            integrity = self.results["integrity"]
            if not integrity.get("overall_integrity", False):
                overall_health = "NEEDS_IMPROVEMENT"
                critical_issues.append("System integrity issues detected")
                recommendations.append("Install missing CLAUDE.md system components")

        return {
            "timestamp": datetime.now().isoformat(),
            "project_name": self.project_root.name,
            "overall_health": overall_health,
            "system_results": self.results,
            "critical_issues": critical_issues,
            "recommendations": recommendations,
            "summary": {
                "systems_run": len(self.results),
                "successful_systems": len([r for r in self.results.values() if r.get("success", False)]),
                "critical_issues_count": len(critical_issues),
                "recommendations_count": len(recommendations),
            },
        }

    def run_complete_system(self, systems_to_run: Optional[list[str]] = None) -> dict:
        """Run complete CLAUDE.md system integration.

        Args:
            systems_to_run: List of specific systems to run, or None for all
        """
        if systems_to_run is None:
            systems_to_run = ["integrity", "documentation", "self_validation", "freshness"]

        # Run system integrity check
        if "integrity" in systems_to_run:
            self.results["integrity"] = self.validate_system_integrity()

        # Run documentation validation
        if "documentation" in systems_to_run:
            self.results["documentation"] = self.run_documentation_validation()

        # Run self-validation
        if "self_validation" in systems_to_run:
            self.results["self_validation"] = self.run_self_validation()

        # Run freshness monitoring
        if "freshness" in systems_to_run:
            self.results["freshness"] = self.run_freshness_monitoring()

        # Generate comprehensive report
        comprehensive_report = self.generate_comprehensive_report()

        # Print summary

        overall_health = comprehensive_report["overall_health"]
        {
            "EXCELLENT": "✅",
            "GOOD": "🟢",
            "NEEDS_IMPROVEMENT": "🟡",
            "CRITICAL": "🔴",
        }.get(overall_health, "❓")

        # Show key results
        for system_name, result in self.results.items():
            if system_name == "integrity":
                continue
            "✅" if result.get("success", False) else "❌"

        # Show critical issues
        if comprehensive_report["critical_issues"]:
            for _i, _issue in enumerate(comprehensive_report["critical_issues"], 1):
                pass

        # Show recommendations
        if comprehensive_report["recommendations"]:
            for _i, _rec in enumerate(comprehensive_report["recommendations"], 1):
                pass

        return comprehensive_report


def main() -> None:
    """Main execution with command line interface."""
    parser = argparse.ArgumentParser(description="CLAUDE.md Complete System Integration")
    parser.add_argument("--project-root", type=Path, default=Path.cwd(),
                       help="Project root directory (default: current directory)")
    parser.add_argument("--systems", nargs="*",
                       choices=["integrity", "documentation", "self_validation", "freshness"],
                       help="Specific systems to run (default: all)")
    parser.add_argument("--output", type=Path,
                       help="Output file for comprehensive report (default: claude_complete_report.json)")

    args = parser.parse_args()

    # Initialize complete system
    complete_system = CLAUDECompleteSystem(args.project_root)

    # Run complete system
    report = complete_system.run_complete_system(args.systems)

    # Save comprehensive report
    output_file = args.output or (args.project_root / "claude_complete_report.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    # Update system memory
    system_memory_file = args.project_root / ".system_memory"
    with open(system_memory_file, "a", encoding="utf-8") as f:
        f.write(f"\nCLAUDE_COMPLETE_SYSTEM_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{report['overall_health']}")

    # Exit with appropriate code
    success_code = 0 if report["overall_health"] in {"EXCELLENT", "GOOD"} else 1
    sys.exit(success_code)


if __name__ == "__main__":
    main()

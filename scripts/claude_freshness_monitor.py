#!/usr/bin/env python3
"""CLAUDE.md Automated Freshness Monitoring System.

Implements the automated freshness monitoring protocols specified in
CLAUDE.md for maintaining documentation currency and quality.

DESIGN PATTERN: DOCUMENTATION FRESHNESS MONITORING (CLAUDE.md Protocol)
=======================================================================

This script implements AUTOMATED DOCUMENTATION UPDATE PROTOCOL from CLAUDE.md:
- Pre-update validation
- Update execution with validation
- Post-update verification
- Freshness tracking and alerting
- Cross-reference validation

References:
- /home/marlonsc/CLAUDE.md → Universal principles (AUTOMATED DOCUMENTATION UPDATE PROTOCOL)
- ../CLAUDE.md → PyAuto workspace patterns
- ./CLAUDE.local.md → Project-specific issues
"""

import json
import re
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass
class FreshnessReport:
    """Freshness monitoring report following CLAUDE.md patterns."""
    timestamp: str
    project_name: str
    files_checked: int
    stale_files: list[dict]
    freshness_violations: list[dict]
    update_recommendations: list[str]
    overall_status: str


class CLAUDEFreshnessMonitor:
    """CLAUDE.md Automated Freshness Monitoring System.

    Implements systematic freshness monitoring for documentation
    hierarchy as specified in CLAUDE.md AUTOMATED DOCUMENTATION
    UPDATE PROTOCOL.

    MONITORING CATEGORIES:
    - Documentation freshness validation
    - Cross-reference currency checking
    - Update recommendation generation
    - Automated backup and validation
    - Freshness alerting system
    """

    def __init__(self, project_root: Path) -> None:
        """Initialize freshness monitoring system."""
        self.project_root = Path(project_root)
        self.workspace_root = self.project_root.parent
        self.global_root = Path("/home/marlonsc")

        # Freshness thresholds (from CLAUDE.md)
        self.freshness_thresholds = {
            "critical": 7,    # CLAUDE.md files should be updated weekly
            "warning": 30,    # General documentation monthly
            "stale": 90,       # Consider stale after 3 months
        }

        # Files to monitor
        self.monitored_files = [
            self.global_root / "CLAUDE.md",
            self.global_root / "CLAUDE.local.md",
            self.workspace_root / "CLAUDE.md",
            self.workspace_root / "CLAUDE.local.md",
            self.project_root / "CLAUDE.local.md",
        ]

    def check_file_freshness(self, file_path: Path) -> dict:
        """Check freshness of individual file.

        CLAUDE.md REQUIREMENT: Automated freshness tracking with
        specific thresholds for different document types.
        """
        if not file_path.exists():
            return {
                "file": str(file_path),
                "status": "MISSING",
                "days_since_update": None,
                "freshness_level": "CRITICAL",
            }

        # Get last modification time
        mod_time = datetime.fromtimestamp(file_path.stat().st_mtime)
        days_since_mod = (datetime.now() - mod_time).days

        # Check for "Last Updated" field in content
        content = file_path.read_text()
        last_updated_match = re.search(r"Last Updated.*?(\d{4}-\d{2}-\d{2})", content)

        if last_updated_match:
            last_updated = datetime.strptime(last_updated_match.group(1), "%Y-%m-%d")
            days_since_update = (datetime.now() - last_updated).days
        else:
            days_since_update = days_since_mod

        # Determine freshness level
        if days_since_update <= self.freshness_thresholds["critical"]:
            freshness_level = "FRESH"
        elif days_since_update <= self.freshness_thresholds["warning"]:
            freshness_level = "WARNING"
        elif days_since_update <= self.freshness_thresholds["stale"]:
            freshness_level = "STALE"
        else:
            freshness_level = "CRITICAL"

        return {
            "file": str(file_path),
            "status": "EXISTS",
            "last_modified": mod_time.isoformat(),
            "last_updated_field": last_updated.isoformat() if last_updated_match else None,
            "days_since_update": days_since_update,
            "freshness_level": freshness_level,
        }

    def validate_cross_references_freshness(self) -> list[dict]:
        """Validate that cross-references point to fresh documents.

        CLAUDE.md REQUIREMENT: Cross-reference validation with
        freshness checking of referenced documents.
        """
        cross_ref_issues = []

        for file_path in self.monitored_files:
            if not file_path.exists():
                continue

            content = file_path.read_text()

            # Find reference patterns
            ref_patterns = [
                r"Reference.*?→\s*([^\n]+)",
                r"See\s+`([^`]+)`",
            ]

            for pattern in ref_patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    ref_text = match

                    # Check if reference points to a CLAUDE.md file
                    if "CLAUDE.md" in ref_text or "CLAUDE.local.md" in ref_text:
                        # Extract file path if possible
                        if "/" in ref_text:
                            ref_path_text = ref_text.split("→")[0].strip() if "→" in ref_text else ref_text

                            # Try to resolve path
                            if ref_path_text.startswith("/"):
                                ref_path = Path(ref_path_text)
                            elif ref_path_text.startswith("../"):
                                ref_path = (file_path.parent / ref_path_text).resolve()
                            else:
                                continue  # Skip relative references we can't resolve

                            if ref_path.exists():
                                ref_freshness = self.check_file_freshness(ref_path)

                                if ref_freshness["freshness_level"] in {"STALE", "CRITICAL"}:
                                    cross_ref_issues.append({
                                        "referencing_file": str(file_path),
                                        "referenced_file": str(ref_path),
                                        "reference_text": ref_text,
                                        "referenced_freshness": ref_freshness["freshness_level"],
                                        "days_since_update": ref_freshness["days_since_update"],
                                    })

        return cross_ref_issues

    def generate_update_recommendations(self, freshness_results: list[dict]) -> list[str]:
        """Generate update recommendations based on freshness analysis.

        CLAUDE.md REQUIREMENT: Update recommendation generation
        with specific actions for different freshness levels.
        """
        recommendations = []

        # Analyze freshness results
        critical_files = [f for f in freshness_results if f["freshness_level"] == "CRITICAL"]
        stale_files = [f for f in freshness_results if f["freshness_level"] == "STALE"]
        warning_files = [f for f in freshness_results if f["freshness_level"] == "WARNING"]

        # Critical recommendations
        if critical_files:
            recommendations.append(f"URGENT: Update {len(critical_files)} critical files (>90 days stale)")
            # Show first 3
            recommendations.extend(f"  - {Path(file_info['file']).name}: {file_info['days_since_update']} days stale" for file_info in critical_files[:3])

        # Stale recommendations
        if stale_files:
            recommendations.append(f"HIGH PRIORITY: Update {len(stale_files)} stale files (>30 days)")
            # Show first 3
            recommendations.extend(f"  - {Path(file_info['file']).name}: {file_info['days_since_update']} days stale" for file_info in stale_files[:3])

        # Warning recommendations
        if warning_files:
            recommendations.append(f"MEDIUM PRIORITY: Review {len(warning_files)} files approaching staleness (>7 days)")

        # Specific CLAUDE.md recommendations
        global_claude = next((f for f in freshness_results if "CLAUDE.md" in f["file"] and "/home/marlonsc" in f["file"]), None)
        if global_claude and global_claude["freshness_level"] != "FRESH":
            recommendations.append("CRITICAL: Global CLAUDE.md requires immediate update (universal methodology)")

        workspace_claude = next((f for f in freshness_results if "CLAUDE.md" in f["file"] and self.workspace_root.name in f["file"]), None)
        if workspace_claude and workspace_claude["freshness_level"] != "FRESH":
            recommendations.append("HIGH: Workspace CLAUDE.md requires update (workspace patterns)")

        project_claude = next((f for f in freshness_results if "CLAUDE.local.md" in f["file"] and self.project_root.name in f["file"]), None)
        if project_claude and project_claude["freshness_level"] in {"STALE", "CRITICAL"}:
            recommendations.append("MEDIUM: Project CLAUDE.local.md requires update (project specifics)")

        return recommendations

    def create_automated_backup(self) -> dict:
        """Create automated backup before updates.

        CLAUDE.md REQUIREMENT: Pre-update validation with backup creation
        and safety measures.
        """
        backup_info = {
            "timestamp": datetime.now().isoformat(),
            "backup_location": None,
            "files_backed_up": [],
            "success": False,
        }

        try:
            # Create backup directory
            backup_dir = self.project_root / f"backup_claude_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            backup_dir.mkdir(exist_ok=True)

            # Backup all CLAUDE files
            for file_path in self.monitored_files:
                if file_path.exists():
                    backup_file = backup_dir / f"{file_path.parent.name}_{file_path.name}"
                    shutil.copy2(file_path, backup_file)
                    backup_info["files_backed_up"].append(str(file_path))

            backup_info["backup_location"] = str(backup_dir)
            backup_info["success"] = True

        except Exception as e:
            backup_info["error"] = str(e)

        return backup_info

    def validate_syntax_and_references(self, file_path: Path) -> dict:
        """Validate document syntax and references.

        CLAUDE.md REQUIREMENT: Post-update verification with
        syntax validation and reference checking.
        """
        validation_result = {
            "file": str(file_path),
            "syntax_valid": True,
            "references_valid": True,
            "issues": [],
        }

        if not file_path.exists():
            validation_result["syntax_valid"] = False
            validation_result["issues"].append("File does not exist")
            return validation_result

        try:
            content = file_path.read_text()

            # Check for required sections in CLAUDE files
            if "CLAUDE" in file_path.name:
                required_patterns = [
                    r"#{1,3}\s+.*CONFIGURATION",  # Configuration section
                    r"Reference.*?→",              # Reference pattern
                    r"Last Updated.*?\d{4}-\d{2}-\d{2}",  # Last updated field
                ]

                for pattern in required_patterns:
                    if not re.search(pattern, content):
                        validation_result["syntax_valid"] = False
                        validation_result["issues"].append(f"Missing required pattern: {pattern}")

            # Validate cross-references
            ref_patterns = [r"Reference.*?→\s*([^\n]+)"]
            for pattern in ref_patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    if "/" in match and not match.startswith("http"):
                        # Try to resolve file reference
                        ref_path = match.split("→")[0].strip() if "→" in match else match

                        if ref_path.startswith("/"):
                            resolved_path = Path(ref_path)
                        elif ref_path.startswith("../"):
                            resolved_path = (file_path.parent / ref_path).resolve()
                        else:
                            continue

                        if not resolved_path.exists():
                            validation_result["references_valid"] = False
                            validation_result["issues"].append(f"Broken reference: {ref_path}")

        except Exception as e:
            validation_result["syntax_valid"] = False
            validation_result["issues"].append(f"Validation error: {e!s}")

        return validation_result

    def run_freshness_monitoring(self) -> FreshnessReport:
        """Run comprehensive freshness monitoring.

        CLAUDE.md REQUIREMENT: Complete freshness monitoring system
        with automated checks and recommendations.
        """
        # Check freshness of all monitored files
        freshness_results = []

        for file_path in self.monitored_files:
            result = self.check_file_freshness(file_path)
            freshness_results.append(result)

            {
                "FRESH": "✅",
                "WARNING": "⚠️",
                "STALE": "🟡",
                "CRITICAL": "🔴",
                "MISSING": "❌",
            }.get(result["freshness_level"], "❓")

            Path(result["file"]).name
            result["days_since_update"]

        # Check cross-reference freshness
        cross_ref_issues = self.validate_cross_references_freshness()

        if cross_ref_issues:
            for issue in cross_ref_issues[:3]:  # Show first 3
                Path(issue["referencing_file"]).name
                Path(issue["referenced_file"]).name

        # Generate recommendations
        recommendations = self.generate_update_recommendations(freshness_results)

        # Determine overall status
        critical_count = len([f for f in freshness_results if f["freshness_level"] == "CRITICAL"])
        stale_count = len([f for f in freshness_results if f["freshness_level"] == "STALE"])

        if critical_count > 0:
            overall_status = "CRITICAL"
        elif stale_count > 0:
            overall_status = "NEEDS_UPDATE"
        elif len([f for f in freshness_results if f["freshness_level"] == "WARNING"]) > 0:
            overall_status = "WARNING"
        else:
            overall_status = "FRESH"

        # Create report
        report = FreshnessReport(
            timestamp=datetime.now().isoformat(),
            project_name=self.project_root.name,
            files_checked=len(freshness_results),
            stale_files=[f for f in freshness_results if f["freshness_level"] in {"STALE", "CRITICAL"}],
            freshness_violations=cross_ref_issues,
            update_recommendations=recommendations,
            overall_status=overall_status,
        )

        # Print summary
        {
            "FRESH": "✅",
            "WARNING": "⚠️",
            "NEEDS_UPDATE": "🟡",
            "CRITICAL": "🔴",
        }.get(overall_status, "❓")

        if recommendations:
            for _i, _rec in enumerate(recommendations[:5], 1):  # Show first 5
                pass

        return report


def main() -> None:
    """Main freshness monitoring execution following CLAUDE.md protocols."""
    project_root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()

    # Initialize freshness monitor
    monitor = CLAUDEFreshnessMonitor(project_root)

    # Run freshness monitoring
    report = monitor.run_freshness_monitoring()

    # Save report
    report_file = project_root / "freshness_report.json"
    with open(report_file, "w", encoding="utf-8") as f:
        report_dict = {
            "timestamp": report.timestamp,
            "project_name": report.project_name,
            "files_checked": report.files_checked,
            "stale_files": report.stale_files,
            "freshness_violations": report.freshness_violations,
            "update_recommendations": report.update_recommendations,
            "overall_status": report.overall_status,
        }
        json.dump(report_dict, f, indent=2)

    # Update freshness memory
    freshness_memory_file = project_root / ".freshness_memory"
    with open(freshness_memory_file, "a", encoding="utf-8") as f:
        f.write(f"\nFRESHNESS_CHECK_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{report.overall_status}")

    # Exit with appropriate code
    success_code = 0 if report.overall_status in {"FRESH", "WARNING"} else 1
    sys.exit(success_code)


if __name__ == "__main__":
    main()

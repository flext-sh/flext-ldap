#!/usr/bin/env python3
"""Documentation Maintenance Orchestrator.

Comprehensive maintenance system that coordinates all documentation quality assurance tasks.
Provides automated workflows and comprehensive reporting.
"""

import argparse
import json
import sys
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

import yaml

# Add parent directory to path for imports
sys.path.insert(0, Path(Path(Path(__file__).resolve()).parent).parent)

# Import documentation quality tools
from audit import DocumentationAuditor
from optimize import ContentOptimizer
from report import ReportGenerator
from sync import DocumentationSync
from validate_links import LinkValidator
from validate_style import StyleValidator

# Constants for maintenance effectiveness calculation
EXCELLENT_QUALITY_THRESHOLD = 90
EXCELLENT_ISSUES_MAX = 0
GOOD_QUALITY_THRESHOLD = 80
GOOD_ISSUES_MAX = 5
FAIR_QUALITY_THRESHOLD = 70
FAIR_ISSUES_MAX = 15
CRITICAL_ISSUES_THRESHOLD = 10
CRITICAL_QUALITY_THRESHOLD = 70


@dataclass
class MaintenanceResult:
    """Result of a maintenance operation."""

    operation: str
    success: bool
    duration: float
    details: dict[str, object]
    timestamp: datetime


@dataclass
class MaintenanceReport:
    """Comprehensive maintenance report."""

    session_id: str
    timestamp: datetime
    operations_run: list[MaintenanceResult]
    overall_success: bool
    total_duration: float
    summary: dict[str, object]


class DocumentationMaintainer:
    """Main documentation maintenance orchestrator."""

    def __init__(self, config_path: str | None = None) -> None:
        """Initialize documentation maintenance orchestrator with optional config path."""
        self.config_path = config_path or str(Path(__file__).parent / "config.yaml")
        self.config = self._load_config()
        self.session_id = f"maintenance_{int(time.time())}"
        self.results: list[MaintenanceResult] = []

    def _load_config(self) -> dict[str, object]:
        """Load configuration."""
        try:
            with Path(self.config_path).open(encoding="utf-8") as f:
                return yaml.safe_load(f)
        except Exception:
            return {}

    def run_comprehensive_maintenance(self) -> MaintenanceReport:
        """Run comprehensive maintenance suite."""
        start_time = time.time()

        # 1. Content Quality Audit
        audit_result = self._run_audit()
        self.results.append(audit_result)

        # 2. Link Validation
        link_result = self._run_link_validation()
        self.results.append(link_result)

        # 3. Style Validation
        style_result = self._run_style_validation()
        self.results.append(style_result)

        # 4. Content Optimization
        optimize_result = self._run_content_optimization()
        self.results.append(optimize_result)

        # 5. Generate Reports
        report_result = self._run_report_generation()
        self.results.append(report_result)

        # 6. Synchronization (optional)
        if self.config.get("sync", {}).get("auto_commit", False):
            sync_result = self._run_synchronization()
            self.results.append(sync_result)

        total_duration = time.time() - start_time
        overall_success = all(r.success for r in self.results)

        summary = self._generate_summary()

        report = MaintenanceReport(
            session_id=self.session_id,
            timestamp=datetime.now(UTC),
            operations_run=self.results,
            overall_success=overall_success,
            total_duration=total_duration,
            summary=summary,
        )

        # Save detailed report
        self._save_report(report)

        return report

    def _run_audit(self) -> MaintenanceResult:
        """Run content quality audit."""
        start_time = time.time()

        try:
            auditor = DocumentationAuditor(self.config_path)

            docs_dir = Path(__file__).parent.parent / "docs"
            results = auditor.audit_directory(docs_dir)
            summary = auditor.generate_summary()

            return MaintenanceResult(
                operation="content_audit",
                success=True,
                duration=time.time() - start_time,
                details={
                    "files_audited": len(results),
                    "total_words": summary.total_words,
                    "average_quality": summary.average_quality,
                    "critical_issues": summary.critical_issues,
                },
                timestamp=datetime.now(UTC),
            )

        except Exception as e:
            return MaintenanceResult(
                operation="content_audit",
                success=False,
                duration=time.time() - start_time,
                details={"error": str(e)},
                timestamp=datetime.now(UTC),
            )

    def _run_link_validation(self) -> MaintenanceResult:
        """Run link validation."""
        start_time = time.time()

        try:
            validator = LinkValidator(self.config_path)

            docs_dir = Path(__file__).parent.parent / "docs"
            results = validator.validate_directory(docs_dir, check_external=True)
            summary = validator.generate_summary(results)

            return MaintenanceResult(
                operation="link_validation",
                success=True,
                duration=time.time() - start_time,
                details={
                    "files_checked": len(results),
                    "broken_links": summary.broken_links,
                    "external_links": summary.external_links,
                    "internal_links": summary.internal_links,
                },
                timestamp=datetime.now(UTC),
            )

        except Exception as e:
            return MaintenanceResult(
                operation="link_validation",
                success=False,
                duration=time.time() - start_time,
                details={"error": str(e)},
                timestamp=datetime.now(UTC),
            )

    def _run_style_validation(self) -> MaintenanceResult:
        """Run style validation."""
        start_time = time.time()

        try:
            validator = StyleValidator(self.config_path)

            docs_dir = Path(__file__).parent.parent / "docs"
            results = validator.validate_directory(docs_dir)
            summary = validator.generate_summary(results)

            return MaintenanceResult(
                operation="style_validation",
                success=True,
                duration=time.time() - start_time,
                details={
                    "files_checked": len(results),
                    "total_violations": summary.total_violations,
                    "average_score": summary.average_score,
                    "files_with_issues": summary.files_with_violations,
                },
                timestamp=datetime.now(UTC),
            )

        except Exception as e:
            return MaintenanceResult(
                operation="style_validation",
                success=False,
                duration=time.time() - start_time,
                details={"error": str(e)},
                timestamp=datetime.now(UTC),
            )

    def _run_content_optimization(self) -> MaintenanceResult:
        """Run content optimization."""
        start_time = time.time()

        try:
            optimizer = ContentOptimizer(self.config_path)

            docs_dir = Path(__file__).parent.parent / "docs"
            results = optimizer.optimize_directory(docs_dir)
            summary = optimizer.generate_summary(results)

            return MaintenanceResult(
                operation="content_optimization",
                success=True,
                duration=time.time() - start_time,
                details={
                    "files_processed": len(results),
                    "total_changes": summary.total_changes,
                    "files_modified": summary.files_modified,
                    "backups_created": len(summary.backup_files_created),
                },
                timestamp=datetime.now(UTC),
            )

        except Exception as e:
            return MaintenanceResult(
                operation="content_optimization",
                success=False,
                duration=time.time() - start_time,
                details={"error": str(e)},
                timestamp=datetime.now(UTC),
            )

    def _run_report_generation(self) -> MaintenanceResult:
        """Generate quality reports."""
        start_time = time.time()

        try:
            generator = ReportGenerator(self.config_path)

            report_data = generator.generate_comprehensive_report()

            # Generate multiple report formats
            dashboard_file = generator.generate_dashboard(report_data)
            summary_file = generator.generate_weekly_summary(report_data)

            return MaintenanceResult(
                operation="report_generation",
                success=True,
                duration=time.time() - start_time,
                details={
                    "dashboard_generated": bool(dashboard_file),
                    "summary_generated": bool(summary_file),
                    "quality_score": report_data.audit_summary.get(
                        "average_quality", 0
                    ),
                },
                timestamp=datetime.now(UTC),
            )

        except Exception as e:
            return MaintenanceResult(
                operation="report_generation",
                success=False,
                duration=time.time() - start_time,
                details={"error": str(e)},
                timestamp=datetime.now(UTC),
            )

    def _run_synchronization(self) -> MaintenanceResult:
        """Run synchronization."""
        start_time = time.time()

        try:
            sync_manager = DocumentationSync(self.config_path)

            # Get pending changes
            status = sync_manager.get_sync_status()
            if status.pending_changes:
                result = sync_manager.sync_changes(
                    "automated_maintenance", status.pending_changes
                )

                return MaintenanceResult(
                    operation="synchronization",
                    success=result.success,
                    duration=time.time() - start_time,
                    details={
                        "files_synced": len(result.files_affected),
                        "sync_success": result.success,
                    },
                    timestamp=datetime.now(UTC),
                )
            return MaintenanceResult(
                operation="synchronization",
                success=True,
                duration=time.time() - start_time,
                details={"message": "No changes to synchronize"},
                timestamp=datetime.now(UTC),
            )

        except Exception as e:
            return MaintenanceResult(
                operation="synchronization",
                success=False,
                duration=time.time() - start_time,
                details={"error": str(e)},
                timestamp=datetime.now(UTC),
            )

    def _generate_summary(self) -> dict[str, object]:
        """Generate overall maintenance summary."""
        successful_ops = sum(1 for r in self.results if r.success)
        total_ops = len(self.results)
        total_duration = sum(r.duration for r in self.results)

        # Aggregate key metrics
        total_files_processed = 0
        total_issues = 0
        quality_scores = []

        for result in self.results:
            if result.operation == "content_audit":
                total_files_processed = max(
                    total_files_processed, result.details.get("files_audited", 0)
                )
                total_issues += result.details.get("critical_issues", 0)
                if "average_quality" in result.details:
                    quality_scores.append(result.details["average_quality"])

            elif result.operation in {"link_validation", "style_validation"}:
                total_files_processed = max(
                    total_files_processed, result.details.get("files_checked", 0)
                )
                if result.operation == "link_validation":
                    total_issues += result.details.get("broken_links", 0)
                else:
                    total_issues += result.details.get("total_violations", 0)

            elif (
                result.operation == "style_validation"
                and "average_score" in result.details
            ):
                quality_scores.append(result.details["average_score"])

        average_quality = (
            sum(quality_scores) / len(quality_scores) if quality_scores else 0
        )

        return {
            "operations_completed": successful_ops,
            "total_operations": total_ops,
            "success_rate": (successful_ops / total_ops * 100) if total_ops > 0 else 0,
            "total_duration": total_duration,
            "files_processed": total_files_processed,
            "total_issues": total_issues,
            "average_quality_score": average_quality,
            "maintenance_effectiveness": self._calculate_effectiveness(
                average_quality, total_issues
            ),
        }

    def _calculate_effectiveness(self, quality_score: float, issues: int) -> str:
        """Calculate maintenance effectiveness rating."""
        if (
            quality_score >= EXCELLENT_QUALITY_THRESHOLD
            and issues == EXCELLENT_ISSUES_MAX
        ):
            return "excellent"
        if quality_score >= GOOD_QUALITY_THRESHOLD and issues <= GOOD_ISSUES_MAX:
            return "good"
        if quality_score >= FAIR_QUALITY_THRESHOLD and issues <= FAIR_ISSUES_MAX:
            return "fair"
        return "needs_attention"

    def save_report(self, report: MaintenanceReport) -> None:
        """Save detailed maintenance report."""
        reports_dir = Path(__file__).parent / "reports"
        reports_dir.mkdir(exist_ok=True, parents=True)

        report_file = reports_dir / f"maintenance_{self.session_id}.json"

        with report_file.open("w", encoding="utf-8") as f:
            # Convert dataclasses to dicts for JSON serialization
            report_dict = {
                "session_id": report.session_id,
                "timestamp": report.timestamp.isoformat(),
                "operations_run": [asdict(op) for op in report.operations_run],
                "overall_success": report.overall_success,
                "total_duration": report.total_duration,
                "summary": report.summary,
            }
            json.dump(report_dict, f, indent=2, default=str)


def main() -> None:
    """Main entry point for documentation maintenance system."""
    parser = argparse.ArgumentParser(
        description="Documentation Maintenance Orchestrator"
    )
    parser.add_argument(
        "--comprehensive",
        action="store_true",
        help="Run comprehensive maintenance suite",
    )
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--output", "-o", help="Output report file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes",
    )

    args = parser.parse_args()

    maintainer = DocumentationMaintainer(args.config)

    if args.comprehensive or not any([args.comprehensive]):
        # Default to comprehensive maintenance
        report = maintainer.run_comprehensive_maintenance()

        # Print results
        report.summary["success_rate"]
        # Overall status
        if report.overall_success:
            pass

        # Operation results
        for result in report.operations_run:
            details = result.details

            if args.verbose and details:
                for key in details:
                    if key != "error":
                        pass

        # Recommendations
        effectiveness = report.summary["maintenance_effectiveness"]
        if effectiveness in {"needs_attention", "fair"}:
            if report.summary["total_issues"] > CRITICAL_ISSUES_THRESHOLD:
                pass
            if report.summary["average_quality_score"] < CRITICAL_QUALITY_THRESHOLD:
                pass
        elif effectiveness == "good":
            pass
        # Save report if requested
        if args.output:
            maintainer.save_report(report)


if __name__ == "__main__":
    main()

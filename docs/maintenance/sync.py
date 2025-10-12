#!/usr/bin/env python3
"""Documentation Synchronization and Automated Maintenance System.

Manages version control integration, automated updates, and synchronization
across documentation repositories.
"""

import argparse
import os
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from flext_core import FlextCore


@dataclass
class SyncResult:
    """Result of a synchronization operation."""

    operation: str
    success: bool
    changes_made: int
    files_affected: FlextCore.Types.StringList
    error_message: str | None
    timestamp: datetime


@dataclass
class SyncStatus:
    """Current synchronization status."""

    git_status: dict[str, Any]
    pending_changes: FlextCore.Types.StringList
    last_sync: datetime | None
    sync_needed: bool
    conflicts_present: bool


class DocumentationSync:
    """Main documentation synchronization class."""

    def __init__(self, config_path: str | None = None) -> None:
        self.config = self._load_config(config_path)
        self.working_dir = Path(Path(Path(__file__).resolve()).parent).parent

    def _load_config(self, config_path: str | None = None) -> dict[str, Any]:
        """Load configuration."""
        default_config = {
            "sync": {
                "auto_commit": False,
                "commit_message_template": "docs: {operation} - {changes} changes",
                "backup_before_changes": True,
                "validate_before_commit": True,
                "push_after_commit": False,
            },
            "git": {
                "remote_name": "origin",
                "main_branch": "main",
                "create_backup_branch": True,
            },
            "maintenance": {
                "schedule": {
                    "daily": ["validate_links"],
                    "weekly": ["comprehensive_audit", "optimize_content"],
                    "monthly": ["update_metadata", "generate_reports"],
                }
            },
        }

        if config_path and Path(config_path).exists():
            with Path(config_path).open(encoding="utf-8") as f:
                user_config = yaml.safe_load(f)
                for key, value in user_config.items():
                    if key in default_config:
                        default_config[key].update(value)
                    else:
                        default_config[key] = value

        return default_config

    def get_sync_status(self) -> SyncStatus:
        """Get current synchronization status."""
        git_status = self._get_git_status()
        pending_changes = self._get_pending_changes()
        last_sync = self._get_last_sync_time()
        sync_needed = len(pending_changes) > 0
        conflicts_present = self._check_for_conflicts()

        return SyncStatus(
            git_status=git_status,
            pending_changes=pending_changes,
            last_sync=last_sync,
            sync_needed=sync_needed,
            conflicts_present=conflicts_present,
        )

    def _get_git_status(self) -> dict[str, Any]:
        """Get git repository status."""
        try:
            # Check if we're in a git repository
            result = subprocess.run(
                ["git", "rev-parse", "--git-dir"],
                check=False,
                cwd=self.working_dir,
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                return {"initialized": False, "message": "Not a git repository"}

            # Get branch info
            branch_result = subprocess.run(
                ["git", "branch", "--show-current"],
                check=False,
                cwd=self.working_dir,
                capture_output=True,
                text=True,
            )
            current_branch = (
                branch_result.stdout.strip()
                if branch_result.returncode == 0
                else "unknown"
            )

            # Get status
            status_result = subprocess.run(
                ["git", "status", "--porcelain"],
                check=False,
                cwd=self.working_dir,
                capture_output=True,
                text=True,
            )

            modified_files = []
            untracked_files = []
            if status_result.returncode == 0:
                for line in status_result.stdout.split("\n"):
                    if line.strip():
                        status_code = line[:2]
                        filename = line[3:]
                        if status_code in {"M ", "MM", "AM", "RM"}:
                            modified_files.append(filename)
                        elif status_code == "??":
                            untracked_files.append(filename)

            return {
                "initialized": True,
                "current_branch": current_branch,
                "modified_files": modified_files,
                "untracked_files": untracked_files,
                "has_changes": len(modified_files) > 0 or len(untracked_files) > 0,
            }

        except Exception as e:
            return {"initialized": False, "error": str(e)}

    def _get_pending_changes(self) -> FlextCore.Types.StringList:
        """Get list of pending changes."""
        status = self._get_git_status()
        return status.get("modified_files", []) + status.get("untracked_files", [])

    def _get_last_sync_time(self) -> datetime | None:
        """Get timestamp of last synchronization."""
        # Look for a marker file or check git log
        try:
            result = subprocess.run(
                ["git", "log", "-1", "--format=%ct", "--", "docs/"],
                check=False,
                cwd=self.working_dir,
                capture_output=True,
                text=True,
            )

            if result.returncode == 0 and result.stdout.strip():
                timestamp = int(result.stdout.strip())
                return datetime.fromtimestamp(timestamp)

        except Exception:
            pass

        return None

    def _check_for_conflicts(self) -> bool:
        """Check if there are merge conflicts."""
        try:
            result = subprocess.run(
                ["git", "status", "--porcelain"],
                check=False,
                cwd=self.working_dir,
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                return any("U" in line[:2] for line in result.stdout.split("\n"))

        except Exception:
            pass

        return False

    def validate_before_sync(self) -> SyncResult:
        """Validate documentation before synchronization."""
        try:
            # Run validation checks
            from validate_links import LinkValidator
            from validate_style import StyleValidator

            validator = LinkValidator()
            style_validator = StyleValidator()

            # Quick validation
            link_results = validator.validate_directory(
                os.path.join(self.working_dir, "docs"), check_external=False
            )
            style_results = style_validator.validate_directory(
                os.path.join(self.working_dir, "docs")
            )

            broken_links = sum(len(r.broken_links) for r in link_results)
            style_violations = sum(len(r.violations) for r in style_results)

            issues_found = broken_links + style_violations

            return SyncResult(
                operation="validation",
                success=issues_found == 0,
                changes_made=0,
                files_affected=[],
                error_message=f"Found {issues_found} issues"
                if issues_found > 0
                else None,
                timestamp=datetime.now(UTC),
            )

        except Exception as e:
            return SyncResult(
                operation="validation",
                success=False,
                changes_made=0,
                files_affected=[],
                error_message=f"Validation failed: {e}",
                timestamp=datetime.now(UTC),
            )

    def sync_changes(
        self, operation: str, files: FlextCore.Types.StringList
    ) -> SyncResult:
        """Synchronize changes to git."""
        if not self.config["sync"]["auto_commit"]:
            return SyncResult(
                operation="sync",
                success=False,
                changes_made=0,
                files_affected=[],
                error_message="Auto-commit disabled in configuration",
                timestamp=datetime.now(UTC),
            )

        try:
            # Stage files
            subprocess.run(["git", "add"] + files, cwd=self.working_dir, check=True)

            # Create commit message
            changes_desc = f"{len(files)} files"
            commit_message = self.config["sync"]["commit_message_template"].format(
                operation=operation, changes=changes_desc
            )

            # Commit
            subprocess.run(
                ["git", "commit", "-m", commit_message],
                cwd=self.working_dir,
                check=True,
            )

            # Push if configured
            if self.config["sync"]["push_after_commit"]:
                subprocess.run(
                    [
                        "git",
                        "push",
                        self.config["git"]["remote_name"],
                        self.config["git"]["main_branch"],
                    ],
                    cwd=self.working_dir,
                    check=True,
                )

            return SyncResult(
                operation="sync",
                success=True,
                changes_made=len(files),
                files_affected=files,
                error_message=None,
                timestamp=datetime.now(UTC),
            )

        except subprocess.CalledProcessError as e:
            return SyncResult(
                operation="sync",
                success=False,
                changes_made=0,
                files_affected=[],
                error_message=f"Git operation failed: {e}",
                timestamp=datetime.now(UTC),
            )

    def create_backup_branch(self) -> SyncResult:
        """Create a backup branch before making changes."""
        if not self.config["git"]["create_backup_branch"]:
            return SyncResult(
                operation="backup_branch",
                success=True,
                changes_made=0,
                files_affected=[],
                error_message="Backup branch creation disabled",
                timestamp=datetime.now(UTC),
            )

        try:
            timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
            branch_name = f"docs-backup-{timestamp}"

            subprocess.run(
                ["git", "checkout", "-b", branch_name], cwd=self.working_dir, check=True
            )

            return SyncResult(
                operation="backup_branch",
                success=True,
                changes_made=0,
                files_affected=[],
                error_message=None,
                timestamp=datetime.now(UTC),
            )

        except subprocess.CalledProcessError as e:
            return SyncResult(
                operation="backup_branch",
                success=False,
                changes_made=0,
                files_affected=[],
                error_message=f"Backup branch creation failed: {e}",
                timestamp=datetime.now(UTC),
            )

    def rollback_changes(self, files: FlextCore.Types.StringList) -> SyncResult:
        """Rollback changes to specific files."""
        try:
            subprocess.run(
                ["git", "checkout", "HEAD", "--"] + files,
                cwd=self.working_dir,
                check=True,
            )

            return SyncResult(
                operation="rollback",
                success=True,
                changes_made=len(files),
                files_affected=files,
                error_message=None,
                timestamp=datetime.now(UTC),
            )

        except subprocess.CalledProcessError as e:
            return SyncResult(
                operation="rollback",
                success=False,
                changes_made=0,
                files_affected=[],
                error_message=f"Rollback failed: {e}",
                timestamp=datetime.now(UTC),
            )

    def run_maintenance_schedule(self, schedule_type: str) -> list[SyncResult]:
        """Run scheduled maintenance tasks."""
        if schedule_type not in self.config["maintenance"]["schedule"]:
            return [
                SyncResult(
                    operation="maintenance",
                    success=False,
                    changes_made=0,
                    files_affected=[],
                    error_message=f"Unknown schedule type: {schedule_type}",
                    timestamp=datetime.now(UTC),
                )
            ]

        tasks = self.config["maintenance"]["schedule"][schedule_type]
        results = []

        for task in tasks:
            if task == "validate_links":
                result = self.validate_before_sync()
            elif task == "comprehensive_audit":
                # Run comprehensive audit
                result = self._run_comprehensive_audit()
            elif task == "optimize_content":
                result = self._run_content_optimization()
            elif task == "update_metadata":
                result = self._run_metadata_update()
            elif task == "generate_reports":
                result = self._run_report_generation()
            else:
                result = SyncResult(
                    operation=task,
                    success=False,
                    changes_made=0,
                    files_affected=[],
                    error_message=f"Unknown maintenance task: {task}",
                    timestamp=datetime.now(UTC),
                )

            results.append(result)

        return results

    def _run_comprehensive_audit(self) -> SyncResult:
        """Run comprehensive documentation audit."""
        try:
            from audit import DocumentationAuditor

            auditor = DocumentationAuditor()
            results = auditor.audit_directory(os.path.join(self.working_dir, "docs"))
            auditor.generate_summary()

            return SyncResult(
                operation="comprehensive_audit",
                success=True,
                changes_made=0,  # Audit doesn't make changes
                files_affected=[r.file_path for r in results],
                error_message=None,
                timestamp=datetime.now(UTC),
            )
        except Exception as e:
            return SyncResult(
                operation="comprehensive_audit",
                success=False,
                changes_made=0,
                files_affected=[],
                error_message=str(e),
                timestamp=datetime.now(UTC),
            )

    def _run_content_optimization(self) -> SyncResult:
        """Run content optimization."""
        try:
            from optimize import ContentOptimizer

            optimizer = ContentOptimizer()
            results = optimizer.optimize_directory(
                os.path.join(self.working_dir, "docs")
            )

            files_modified = [r.file_path for r in results if r.changes_made > 0]
            total_changes = sum(r.changes_made for r in results)

            return SyncResult(
                operation="content_optimization",
                success=True,
                changes_made=total_changes,
                files_affected=files_modified,
                error_message=None,
                timestamp=datetime.now(UTC),
            )
        except Exception as e:
            return SyncResult(
                operation="content_optimization",
                success=False,
                changes_made=0,
                files_affected=[],
                error_message=str(e),
                timestamp=datetime.now(UTC),
            )

    def _run_metadata_update(self) -> SyncResult:
        """Update documentation metadata."""
        try:
            # Update timestamps, version info, etc.
            docs_dir = os.path.join(self.working_dir, "docs")
            updated_files = []

            for root, _dirs, files in os.walk(docs_dir):
                for file in files:
                    if file.endswith((".md", ".mdx")):
                        file_path = os.path.join(root, file)
                        # Simple metadata update - could be more sophisticated
                        with Path(file_path).open(encoding="utf-8") as f:
                            content = f.read()

                        # Update last modified timestamp if present
                        if "last_updated:" in content or "updated:" in content:
                            # This would be more complex in practice
                            updated_files.append(file_path)

            return SyncResult(
                operation="metadata_update",
                success=True,
                changes_made=len(updated_files),
                files_affected=updated_files,
                error_message=None,
                timestamp=datetime.now(UTC),
            )
        except Exception as e:
            return SyncResult(
                operation="metadata_update",
                success=False,
                changes_made=0,
                files_affected=[],
                error_message=str(e),
                timestamp=datetime.now(UTC),
            )

    def _run_report_generation(self) -> SyncResult:
        """Generate maintenance reports."""
        try:
            from report import ReportGenerator

            generator = ReportGenerator()
            report_data = generator.generate_comprehensive_report()

            # Generate both dashboard and summary
            dashboard_file = generator.generate_dashboard(report_data)
            summary_file = generator.generate_weekly_summary(report_data)

            return SyncResult(
                operation="report_generation",
                success=True,
                changes_made=2,  # Two files created
                files_affected=[dashboard_file, summary_file],
                error_message=None,
                timestamp=datetime.now(UTC),
            )
        except Exception as e:
            return SyncResult(
                operation="report_generation",
                success=False,
                changes_made=0,
                files_affected=[],
                error_message=str(e),
                timestamp=datetime.now(UTC),
            )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Documentation Synchronization and Automated Maintenance System"
    )
    parser.add_argument(
        "--status", action="store_true", help="Show current synchronization status"
    )
    parser.add_argument(
        "--validate", action="store_true", help="Validate documentation before sync"
    )
    parser.add_argument(
        "--sync", nargs="*", metavar="FILE", help="Synchronize specific files to git"
    )
    parser.add_argument(
        "--backup-branch",
        action="store_true",
        help="Create backup branch before changes",
    )
    parser.add_argument(
        "--rollback",
        nargs="*",
        metavar="FILE",
        help="Rollback changes to specific files",
    )
    parser.add_argument(
        "--maintenance",
        choices=["daily", "weekly", "monthly"],
        help="Run scheduled maintenance tasks",
    )
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    sync = DocumentationSync(args.config)

    if args.status:
        status = sync.get_sync_status()

        git_info = status.git_status
        if git_info.get("initialized"):
            pass

        if status.pending_changes and args.verbose:
            for _change in status.pending_changes[:10]:
                pass
            if len(status.pending_changes) > 10:
                pass

    elif args.validate:
        result = sync.validate_before_sync()

        if result.success:
            pass

    elif args.sync is not None:
        files_to_sync = args.sync or sync.get_sync_status().pending_changes

        if not files_to_sync:
            return

        # Validate first if configured
        if sync.config["sync"]["validate_before_commit"]:
            validation_result = sync.validate_before_sync()
            if not validation_result.success:
                return

        # Create backup branch if configured
        if sync.config["git"]["create_backup_branch"]:
            backup_result = sync.create_backup_branch()
            if not backup_result.success:
                return

        # Sync changes
        result = sync.sync_changes("documentation_update", files_to_sync)

        if result.success and result.files_affected and args.verbose:
            for _file in result.files_affected[:10]:
                pass

    elif args.backup_branch:
        result = sync.create_backup_branch()
        if result.success:
            pass

    elif args.rollback:
        if not args.rollback:
            return

        result = sync.rollback_changes(args.rollback)
        if result.success:
            pass

    elif args.maintenance:
        results = sync.run_maintenance_schedule(args.maintenance)

        sum(1 for r in results if r.success)
        len(results)

        if args.verbose:
            for result in results:
                status = "✅" if result.success else "❌"

    else:
        # Default: show status
        args.status = True
        main()


if __name__ == "__main__":
    main()

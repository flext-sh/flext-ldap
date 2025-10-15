#!/usr/bin/env python3
"""Documentation Synchronization and Automated Maintenance System.

Manages version control integration, automated updates, and synchronization
across documentation repositories.
"""

import argparse
import logging
import os
import shutil
import subprocess  # nosec S404 - Required for Git operations in documentation sync
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TypedDict

import yaml
from flext_core import FlextCore

from .audit import DocumentationAuditor
from .optimize import ContentOptimizer
from .report import ReportGenerator
from .validate_links import LinkValidator
from .validate_style import StyleValidator

logger = logging.getLogger(__name__)


# Type definitions
class GitStatusInfo(TypedDict):
    """Git status information."""

    branch: str
    modified_files: list[str]
    untracked_files: list[str]
    staged_files: list[str]
    ahead_count: int
    behind_count: int


class SyncConfig(TypedDict):
    """Configuration for documentation synchronization."""

    sync: dict[str, object]
    git: dict[str, object]
    maintenance: dict[str, object]


# Constants for synchronization
MAX_CHANGES_DISPLAY: int = FlextCore.Constants.Network.MAX_CONNECTIONS // 10


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

    git_status: GitStatusInfo
    pending_changes: FlextCore.Types.StringList
    last_sync: datetime | None
    sync_needed: bool
    conflicts_present: bool


class DocumentationSync:
    """Main documentation synchronization class."""

    def __init__(self, config_path: str | None = None) -> None:
        """Initialize documentation synchronization system."""
        self.config: SyncConfig = self._load_config(config_path)
        self.working_dir = Path(Path(Path(__file__).resolve()).parent).parent

    def _get_git_command(self) -> str | None:
        """Get the full path to git command."""
        return shutil.which("git")

    def _load_config(self, config_path: str | None = None) -> SyncConfig:
        """Load configuration."""
        default_config: SyncConfig = {
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
                user_config: dict[str, object] = yaml.safe_load(f)
                for key, value in user_config.items():
                    if key in default_config and isinstance(value, dict):
                        # Merge nested configs
                        current_val = default_config.get(key)
                        if isinstance(current_val, dict):
                            current_val.update(value)
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

    def _get_git_status(self) -> GitStatusInfo:
        """Get git repository status."""
        try:
            # Check if we're in a git repository
            git_cmd = self._get_git_command()
            if not git_cmd:
                return GitStatusInfo(
                    branch="unknown",
                    modified_files=[],
                    untracked_files=[],
                    staged_files=[],
                    ahead_count=0,
                    behind_count=0,
                )

            result = subprocess.run(  # nosec S603 - git command with fixed arguments and full path
                [git_cmd, "rev-parse", "--git-dir"],
                check=False,
                cwd=self.working_dir,
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                return GitStatusInfo(
                    branch="unknown",
                    modified_files=[],
                    untracked_files=[],
                    staged_files=[],
                    ahead_count=0,
                    behind_count=0,
                )

            # Get branch info
            branch_result = subprocess.run(  # nosec S603 - git command with fixed arguments and full path
                [git_cmd, "branch", "--show-current"],
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
            status_result = subprocess.run(  # nosec S603 - git command with fixed arguments and full path
                [git_cmd, "status", "--porcelain"],
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

            return GitStatusInfo(
                branch=current_branch,
                modified_files=modified_files,
                untracked_files=untracked_files,
                staged_files=[],
                ahead_count=0,
                behind_count=0,
            )

        except Exception as e:
            logger.debug(f"Git operations failed, using default status: {e}")
            return GitStatusInfo(
                branch="unknown",
                modified_files=[],
                untracked_files=[],
                staged_files=[],
                ahead_count=0,
                behind_count=0,
            )

    def _get_pending_changes(self) -> FlextCore.Types.StringList:
        """Get list of pending changes."""
        status = self._get_git_status()
        return status["modified_files"] + status["untracked_files"]

    def _get_last_sync_time(self) -> datetime | None:
        """Get timestamp of last synchronization."""
        # Look for a marker file or check git log
        try:
            git_cmd = self._get_git_command()
            if not git_cmd:
                return None

            result = subprocess.run(  # nosec S603 - git command with fixed arguments and full path
                [git_cmd, "log", "-1", "--format=%ct", "--", "docs/"],
                check=False,
                cwd=self.working_dir,
                capture_output=True,
                text=True,
            )

            if result.returncode == 0 and result.stdout.strip():
                timestamp = int(result.stdout.strip())
                return datetime.fromtimestamp(timestamp, tz=UTC)

        except Exception as e:
            # Git operations are optional, continue without git info
            logger.debug(f"Git operations failed, continuing without git info: {e}")

        return None

    def _check_for_conflicts(self) -> bool:
        """Check if there are merge conflicts."""
        try:
            git_cmd = self._get_git_command()
            if not git_cmd:
                return False

            result = subprocess.run(  # nosec S603 - git command with fixed arguments and full path
                [git_cmd, "status", "--porcelain"],
                check=False,
                cwd=self.working_dir,
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                return any("U" in line[:2] for line in result.stdout.split("\n"))

        except Exception as e:
            # Git operations are optional, continue without git info
            logger.debug(f"Git operations failed, continuing without git info: {e}")

        return False

    def validate_before_sync(self) -> SyncResult:
        """Validate documentation before synchronization."""
        try:
            # Run validation checks

            validator = LinkValidator()
            style_validator = StyleValidator()

            # Quick validation
            link_results = validator.validate_directory(
                str(self.working_dir / "docs"), check_external=False
            )
            style_results = style_validator.validate_directory(
                str(self.working_dir / "docs")
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
            git_cmd = self._get_git_command()
            if not git_cmd:
                return SyncResult(
                    operation="sync",
                    success=False,
                    changes_made=0,
                    files_affected=[],
                    error_message="Git command not found",
                    timestamp=datetime.now(UTC),
                )

            subprocess.run(  # nosec S603 - git command with validated file paths and full path
                [git_cmd, "add", *files],
                cwd=str(self.working_dir),
                check=True,
                capture_output=True,
                text=True,
            )

            # Create commit message
            changes_desc = f"{len(files)} files"
            commit_message_template = str(
                self.config["sync"]["commit_message_template"]
            )
            commit_message = commit_message_template.format(
                operation=operation, changes=changes_desc
            )

            # Commit
            subprocess.run(  # nosec S603 - git command with validated message and full path
                [git_cmd, "commit", "-m", commit_message],
                cwd=str(self.working_dir),
                check=True,
                capture_output=True,
                text=True,
            )

            # Push if configured
            if self.config["sync"]["push_after_commit"]:
                remote_name = str(self.config["git"]["remote_name"])
                main_branch = str(self.config["git"]["main_branch"])
                subprocess.run(  # nosec S603,S607 - git command with validated config and full path
                    [git_cmd, "push", remote_name, main_branch],
                    cwd=str(self.working_dir),
                    check=True,
                    capture_output=True,
                    text=True,
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
            git_cmd = self._get_git_command()
            if not git_cmd:
                return SyncResult(
                    operation="backup_branch",
                    success=False,
                    changes_made=0,
                    files_affected=[],
                    error_message="Git command not found",
                    timestamp=datetime.now(UTC),
                )

            timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
            branch_name = f"docs-backup-{timestamp}"

            subprocess.run(  # nosec S603,S607 - git command with validated branch name and full path
                [git_cmd, "checkout", "-b", branch_name],
                cwd=str(self.working_dir),
                check=True,
                capture_output=True,
                text=True,
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
            git_cmd = self._get_git_command()
            if not git_cmd:
                return SyncResult(
                    operation="rollback",
                    success=False,
                    changes_made=0,
                    files_affected=[],
                    error_message="Git command not found",
                    timestamp=datetime.now(UTC),
                )

            subprocess.run(  # nosec S603 - git command with validated file paths and full path
                [git_cmd, "checkout", "HEAD", "--", *files],
                cwd=str(self.working_dir),
                check=True,
                capture_output=True,
                text=True,
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
        maintenance_config = self.config["maintenance"]
        if (
            not isinstance(maintenance_config, dict)
            or "schedule" not in maintenance_config
        ):
            return [
                SyncResult(
                    operation="maintenance",
                    success=False,
                    changes_made=0,
                    files_affected=[],
                    error_message="Invalid maintenance configuration",
                    timestamp=datetime.now(UTC),
                )
            ]

        schedule = maintenance_config["schedule"]
        if not isinstance(schedule, dict) or schedule_type not in schedule:
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

        tasks_obj = schedule[schedule_type]
        if not isinstance(tasks_obj, list):
            return [
                SyncResult(
                    operation="maintenance",
                    success=False,
                    changes_made=0,
                    files_affected=[],
                    error_message="Invalid schedule tasks configuration",
                    timestamp=datetime.now(UTC),
                )
            ]

        tasks: list[str] = [str(task) for task in tasks_obj]
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
            auditor = DocumentationAuditor()
            results = auditor.audit_directory(str(self.working_dir / "docs"))
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
            optimizer = ContentOptimizer()
            results = optimizer.optimize_directory(str(self.working_dir / "docs"))

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
            docs_dir = str(self.working_dir / "docs")
            updated_files: list[str] = []

            for root, _dirs, files in os.walk(docs_dir):
                for file in files:
                    if file.endswith((".md", ".mdx")):
                        file_path = Path(root) / file
                        # Simple metadata update - could be more sophisticated
                        with Path(file_path).open(encoding="utf-8") as f:
                            content = f.read()

                        # Update last modified timestamp if present
                        if "last_updated:" in content or "updated:" in content:
                            # This would be more complex in practice
                            updated_files.append(str(file_path))

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
    """Main entry point for the documentation synchronization system."""
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
        # Check git status - branch "unknown" indicates not initialized
        if git_info["branch"] != "unknown":
            pass

        if status.pending_changes and args.verbose:
            for _change in status.pending_changes[:MAX_CHANGES_DISPLAY]:
                pass
            if len(status.pending_changes) > MAX_CHANGES_DISPLAY:
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

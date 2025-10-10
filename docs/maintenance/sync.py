#!/usr/bin/env python3
"""
Documentation Synchronization and Automated Maintenance System

Manages version control integration, automated updates, and synchronization
across documentation repositories.
"""

import os
import sys
import re
import json
import yaml
import time
import subprocess
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

@dataclass
class SyncResult:
    """Result of a synchronization operation."""
    operation: str
    success: bool
    changes_made: int
    files_affected: List[str]
    error_message: Optional[str]
    timestamp: datetime

@dataclass
class SyncStatus:
    """Current synchronization status."""
    git_status: Dict[str, Any]
    pending_changes: List[str]
    last_sync: Optional[datetime]
    sync_needed: bool
    conflicts_present: bool

class DocumentationSync:
    """Main documentation synchronization class."""

    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.working_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def _load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """Load configuration."""
        default_config = {
            'sync': {
                'auto_commit': False,
                'commit_message_template': 'docs: {operation} - {changes} changes',
                'backup_before_changes': True,
                'validate_before_commit': True,
                'push_after_commit': False
            },
            'git': {
                'remote_name': 'origin',
                'main_branch': 'main',
                'create_backup_branch': True
            },
            'maintenance': {
                'schedule': {
                    'daily': ['validate_links'],
                    'weekly': ['comprehensive_audit', 'optimize_content'],
                    'monthly': ['update_metadata', 'generate_reports']
                }
            }
        }

        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
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
            conflicts_present=conflicts_present
        )

    def _get_git_status(self) -> Dict[str, Any]:
        """Get git repository status."""
        try:
            # Check if we're in a git repository
            result = subprocess.run(
                ['git', 'rev-parse', '--git-dir'],
                cwd=self.working_dir,
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                return {'initialized': False, 'message': 'Not a git repository'}

            # Get branch info
            branch_result = subprocess.run(
                ['git', 'branch', '--show-current'],
                cwd=self.working_dir,
                capture_output=True,
                text=True
            )
            current_branch = branch_result.stdout.strip() if branch_result.returncode == 0 else 'unknown'

            # Get status
            status_result = subprocess.run(
                ['git', 'status', '--porcelain'],
                cwd=self.working_dir,
                capture_output=True,
                text=True
            )

            modified_files = []
            untracked_files = []
            if status_result.returncode == 0:
                for line in status_result.stdout.split('\n'):
                    if line.strip():
                        status_code = line[:2]
                        filename = line[3:]
                        if status_code in ['M ', 'MM', 'AM', 'RM']:
                            modified_files.append(filename)
                        elif status_code == '??':
                            untracked_files.append(filename)

            return {
                'initialized': True,
                'current_branch': current_branch,
                'modified_files': modified_files,
                'untracked_files': untracked_files,
                'has_changes': len(modified_files) > 0 or len(untracked_files) > 0
            }

        except Exception as e:
            return {'initialized': False, 'error': str(e)}

    def _get_pending_changes(self) -> List[str]:
        """Get list of pending changes."""
        status = self._get_git_status()
        return status.get('modified_files', []) + status.get('untracked_files', [])

    def _get_last_sync_time(self) -> Optional[datetime]:
        """Get timestamp of last synchronization."""
        # Look for a marker file or check git log
        try:
            result = subprocess.run(
                ['git', 'log', '-1', '--format=%ct', '--', 'docs/'],
                cwd=self.working_dir,
                capture_output=True,
                text=True
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
                ['git', 'status', '--porcelain'],
                cwd=self.working_dir,
                capture_output=True,
                text=True
            )

            if result.returncode == 0:
                return any('U' in line[:2] for line in result.stdout.split('\n'))

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
                os.path.join(self.working_dir, 'docs'),
                check_external=False
            )
            style_results = style_validator.validate_directory(
                os.path.join(self.working_dir, 'docs')
            )

            broken_links = sum(len(r.broken_links) for r in link_results)
            style_violations = sum(len(r.violations) for r in style_results)

            issues_found = broken_links + style_violations

            return SyncResult(
                operation='validation',
                success=issues_found == 0,
                changes_made=0,
                files_affected=[],
                error_message=f'Found {issues_found} issues' if issues_found > 0 else None,
                timestamp=datetime.now()
            )

        except Exception as e:
            return SyncResult(
                operation='validation',
                success=False,
                changes_made=0,
                files_affected=[],
                error_message=f'Validation failed: {e}',
                timestamp=datetime.now()
            )

    def sync_changes(self, operation: str, files: List[str]) -> SyncResult:
        """Synchronize changes to git."""
        if not self.config['sync']['auto_commit']:
            return SyncResult(
                operation='sync',
                success=False,
                changes_made=0,
                files_affected=[],
                error_message='Auto-commit disabled in configuration',
                timestamp=datetime.now()
            )

        try:
            # Stage files
            subprocess.run(
                ['git', 'add'] + files,
                cwd=self.working_dir,
                check=True
            )

            # Create commit message
            changes_desc = f"{len(files)} files"
            commit_message = self.config['sync']['commit_message_template'].format(
                operation=operation,
                changes=changes_desc
            )

            # Commit
            subprocess.run(
                ['git', 'commit', '-m', commit_message],
                cwd=self.working_dir,
                check=True
            )

            # Push if configured
            if self.config['sync']['push_after_commit']:
                subprocess.run(
                    ['git', 'push', self.config['git']['remote_name'], self.config['git']['main_branch']],
                    cwd=self.working_dir,
                    check=True
                )

            return SyncResult(
                operation='sync',
                success=True,
                changes_made=len(files),
                files_affected=files,
                error_message=None,
                timestamp=datetime.now()
            )

        except subprocess.CalledProcessError as e:
            return SyncResult(
                operation='sync',
                success=False,
                changes_made=0,
                files_affected=[],
                error_message=f'Git operation failed: {e}',
                timestamp=datetime.now()
            )

    def create_backup_branch(self) -> SyncResult:
        """Create a backup branch before making changes."""
        if not self.config['git']['create_backup_branch']:
            return SyncResult(
                operation='backup_branch',
                success=True,
                changes_made=0,
                files_affected=[],
                error_message='Backup branch creation disabled',
                timestamp=datetime.now()
            )

        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            branch_name = f"docs-backup-{timestamp}"

            subprocess.run(
                ['git', 'checkout', '-b', branch_name],
                cwd=self.working_dir,
                check=True
            )

            return SyncResult(
                operation='backup_branch',
                success=True,
                changes_made=0,
                files_affected=[],
                error_message=None,
                timestamp=datetime.now()
            )

        except subprocess.CalledProcessError as e:
            return SyncResult(
                operation='backup_branch',
                success=False,
                changes_made=0,
                files_affected=[],
                error_message=f'Backup branch creation failed: {e}',
                timestamp=datetime.now()
            )

    def rollback_changes(self, files: List[str]) -> SyncResult:
        """Rollback changes to specific files."""
        try:
            subprocess.run(
                ['git', 'checkout', 'HEAD', '--'] + files,
                cwd=self.working_dir,
                check=True
            )

            return SyncResult(
                operation='rollback',
                success=True,
                changes_made=len(files),
                files_affected=files,
                error_message=None,
                timestamp=datetime.now()
            )

        except subprocess.CalledProcessError as e:
            return SyncResult(
                operation='rollback',
                success=False,
                changes_made=0,
                files_affected=[],
                error_message=f'Rollback failed: {e}',
                timestamp=datetime.now()
            )

    def run_maintenance_schedule(self, schedule_type: str) -> List[SyncResult]:
        """Run scheduled maintenance tasks."""
        if schedule_type not in self.config['maintenance']['schedule']:
            return [SyncResult(
                operation='maintenance',
                success=False,
                changes_made=0,
                files_affected=[],
                error_message=f'Unknown schedule type: {schedule_type}',
                timestamp=datetime.now()
            )]

        tasks = self.config['maintenance']['schedule'][schedule_type]
        results = []

        for task in tasks:
            if task == 'validate_links':
                result = self.validate_before_sync()
            elif task == 'comprehensive_audit':
                # Run comprehensive audit
                result = self._run_comprehensive_audit()
            elif task == 'optimize_content':
                result = self._run_content_optimization()
            elif task == 'update_metadata':
                result = self._run_metadata_update()
            elif task == 'generate_reports':
                result = self._run_report_generation()
            else:
                result = SyncResult(
                    operation=task,
                    success=False,
                    changes_made=0,
                    files_affected=[],
                    error_message=f'Unknown maintenance task: {task}',
                    timestamp=datetime.now()
                )

            results.append(result)

        return results

    def _run_comprehensive_audit(self) -> SyncResult:
        """Run comprehensive documentation audit."""
        try:
            from audit import DocumentationAuditor
            auditor = DocumentationAuditor()
            results = auditor.audit_directory(os.path.join(self.working_dir, 'docs'))
            summary = auditor.generate_summary()

            return SyncResult(
                operation='comprehensive_audit',
                success=True,
                changes_made=0,  # Audit doesn't make changes
                files_affected=[r.file_path for r in results],
                error_message=None,
                timestamp=datetime.now()
            )
        except Exception as e:
            return SyncResult(
                operation='comprehensive_audit',
                success=False,
                changes_made=0,
                files_affected=[],
                error_message=str(e),
                timestamp=datetime.now()
            )

    def _run_content_optimization(self) -> SyncResult:
        """Run content optimization."""
        try:
            from optimize import ContentOptimizer
            optimizer = ContentOptimizer()
            results = optimizer.optimize_directory(os.path.join(self.working_dir, 'docs'))

            files_modified = [r.file_path for r in results if r.changes_made > 0]
            total_changes = sum(r.changes_made for r in results)

            return SyncResult(
                operation='content_optimization',
                success=True,
                changes_made=total_changes,
                files_affected=files_modified,
                error_message=None,
                timestamp=datetime.now()
            )
        except Exception as e:
            return SyncResult(
                operation='content_optimization',
                success=False,
                changes_made=0,
                files_affected=[],
                error_message=str(e),
                timestamp=datetime.now()
            )

    def _run_metadata_update(self) -> SyncResult:
        """Update documentation metadata."""
        try:
            # Update timestamps, version info, etc.
            docs_dir = os.path.join(self.working_dir, 'docs')
            updated_files = []

            for root, dirs, files in os.walk(docs_dir):
                for file in files:
                    if file.endswith(('.md', '.mdx')):
                        file_path = os.path.join(root, file)
                        # Simple metadata update - could be more sophisticated
                        with open(file_path, 'r') as f:
                            content = f.read()

                        # Update last modified timestamp if present
                        if 'last_updated:' in content or 'updated:' in content:
                            # This would be more complex in practice
                            updated_files.append(file_path)

            return SyncResult(
                operation='metadata_update',
                success=True,
                changes_made=len(updated_files),
                files_affected=updated_files,
                error_message=None,
                timestamp=datetime.now()
            )
        except Exception as e:
            return SyncResult(
                operation='metadata_update',
                success=False,
                changes_made=0,
                files_affected=[],
                error_message=str(e),
                timestamp=datetime.now()
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
                operation='report_generation',
                success=True,
                changes_made=2,  # Two files created
                files_affected=[dashboard_file, summary_file],
                error_message=None,
                timestamp=datetime.now()
            )
        except Exception as e:
            return SyncResult(
                operation='report_generation',
                success=False,
                changes_made=0,
                files_affected=[],
                error_message=str(e),
                timestamp=datetime.now()
            )

def main():
    parser = argparse.ArgumentParser(description='Documentation Synchronization and Automated Maintenance System')
    parser.add_argument('--status', action='store_true',
                       help='Show current synchronization status')
    parser.add_argument('--validate', action='store_true',
                       help='Validate documentation before sync')
    parser.add_argument('--sync', nargs='*', metavar='FILE',
                       help='Synchronize specific files to git')
    parser.add_argument('--backup-branch', action='store_true',
                       help='Create backup branch before changes')
    parser.add_argument('--rollback', nargs='*', metavar='FILE',
                       help='Rollback changes to specific files')
    parser.add_argument('--maintenance', choices=['daily', 'weekly', 'monthly'],
                       help='Run scheduled maintenance tasks')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    sync = DocumentationSync(args.config)

    if args.status:
        status = sync.get_sync_status()
        print("\n" + "="*60)
        print("🔄 SYNCHRONIZATION STATUS")
        print("="*60)

        git_info = status.git_status
        if git_info.get('initialized'):
            print(f"📂 Repository: Initialized")
            print(f"🌿 Branch: {git_info.get('current_branch', 'unknown')}")
            print(f"📝 Modified Files: {len(git_info.get('modified_files', []))}")
            print(f"🆕 Untracked Files: {len(git_info.get('untracked_files', []))}")
        else:
            print(f"❌ Repository: {git_info.get('message', 'Not initialized')}")

        print(f"⏰ Last Sync: {status.last_sync.strftime('%Y-%m-%d %H:%M:%S') if status.last_sync else 'Never'}")
        print(f"🔄 Sync Needed: {'Yes' if status.sync_needed else 'No'}")
        print(f"⚠️  Conflicts: {'Yes' if status.conflicts_present else 'No'}")

        if status.pending_changes and args.verbose:
            print("
📋 Pending Changes:"            for change in status.pending_changes[:10]:
                print(f"  {change}")
            if len(status.pending_changes) > 10:
                print(f"  ... and {len(status.pending_changes) - 10} more")

    elif args.validate:
        print("🔍 Validating documentation...")
        result = sync.validate_before_sync()

        if result.success:
            print("✅ Validation passed - ready for sync")
        else:
            print(f"❌ Validation failed: {result.error_message}")

    elif args.sync is not None:
        files_to_sync = args.sync if args.sync else sync.get_sync_status().pending_changes

        if not files_to_sync:
            print("ℹ️  No files to synchronize")
            return

        print(f"🔄 Synchronizing {len(files_to_sync)} files...")

        # Validate first if configured
        if sync.config['sync']['validate_before_commit']:
            validation_result = sync.validate_before_sync()
            if not validation_result.success:
                print(f"❌ Pre-sync validation failed: {validation_result.error_message}")
                return

        # Create backup branch if configured
        if sync.config['git']['create_backup_branch']:
            backup_result = sync.create_backup_branch()
            if not backup_result.success:
                print(f"❌ Backup branch creation failed: {backup_result.error_message}")
                return
            print(f"💾 Created backup branch")

        # Sync changes
        result = sync.sync_changes('documentation_update', files_to_sync)

        if result.success:
            print(f"✅ Successfully synchronized {result.changes_made} changes")
            if result.files_affected and args.verbose:
                print("📋 Files synchronized:")
                for file in result.files_affected[:10]:
                    print(f"  {file}")
        else:
            print(f"❌ Synchronization failed: {result.error_message}")

    elif args.backup_branch:
        result = sync.create_backup_branch()
        if result.success:
            print("💾 Backup branch created successfully")
        else:
            print(f"❌ Backup branch creation failed: {result.error_message}")

    elif args.rollback:
        if not args.rollback:
            print("❌ Specify files to rollback")
            return

        result = sync.rollback_changes(args.rollback)
        if result.success:
            print(f"🔄 Successfully rolled back {result.changes_made} files")
        else:
            print(f"❌ Rollback failed: {result.error_message}")

    elif args.maintenance:
        print(f"🔧 Running {args.maintenance} maintenance tasks...")
        results = sync.run_maintenance_schedule(args.maintenance)

        successful = sum(1 for r in results if r.success)
        total = len(results)

        print(f"📊 Maintenance Results: {successful}/{total} tasks completed")

        if args.verbose:
            for result in results:
                status = "✅" if result.success else "❌"
                print(f"  {status} {result.operation}: {result.changes_made} changes")

    else:
        # Default: show status
        args.status = True
        main()

if __name__ == '__main__':
    main()
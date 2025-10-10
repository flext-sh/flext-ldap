#!/usr/bin/env python3
"""
Documentation Maintenance Orchestrator

Comprehensive maintenance system that coordinates all documentation quality assurance tasks.
Provides automated workflows and comprehensive reporting.
"""

import os
import sys
import json
import yaml
import time
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

@dataclass
class MaintenanceResult:
    """Result of a maintenance operation."""
    operation: str
    success: bool
    duration: float
    details: Dict[str, Any]
    timestamp: datetime

@dataclass
class MaintenanceReport:
    """Comprehensive maintenance report."""
    session_id: str
    timestamp: datetime
    operations_run: List[MaintenanceResult]
    overall_success: bool
    total_duration: float
    summary: Dict[str, Any]

class DocumentationMaintainer:
    """Main documentation maintenance orchestrator."""

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or os.path.join(os.path.dirname(__file__), 'config.yaml')
        self.config = self._load_config()
        self.session_id = f"maintenance_{int(time.time())}"
        self.results: List[MaintenanceResult] = []

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration."""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"⚠️  Warning: Could not load config file: {e}")
            return {}

    def run_comprehensive_maintenance(self) -> MaintenanceReport:
        """Run comprehensive maintenance suite."""
        start_time = time.time()

        print("🚀 Starting Comprehensive Documentation Maintenance")
        print("="*60)

        # 1. Content Quality Audit
        print("📊 Step 1: Content Quality Audit")
        audit_result = self._run_audit()
        self.results.append(audit_result)

        # 2. Link Validation
        print("🔗 Step 2: Link Validation")
        link_result = self._run_link_validation()
        self.results.append(link_result)

        # 3. Style Validation
        print("📝 Step 3: Style Validation")
        style_result = self._run_style_validation()
        self.results.append(style_result)

        # 4. Content Optimization
        print("🔧 Step 4: Content Optimization")
        optimize_result = self._run_content_optimization()
        self.results.append(optimize_result)

        # 5. Generate Reports
        print("📊 Step 5: Generate Quality Reports")
        report_result = self._run_report_generation()
        self.results.append(report_result)

        # 6. Synchronization (optional)
        if self.config.get('sync', {}).get('auto_commit', False):
            print("🔄 Step 6: Synchronization")
            sync_result = self._run_synchronization()
            self.results.append(sync_result)

        total_duration = time.time() - start_time
        overall_success = all(r.success for r in self.results)

        summary = self._generate_summary()

        report = MaintenanceReport(
            session_id=self.session_id,
            timestamp=datetime.now(),
            operations_run=self.results,
            overall_success=overall_success,
            total_duration=total_duration,
            summary=summary
        )

        # Save detailed report
        self._save_report(report)

        return report

    def _run_audit(self) -> MaintenanceResult:
        """Run content quality audit."""
        start_time = time.time()

        try:
            from audit import DocumentationAuditor
            auditor = DocumentationAuditor(self.config_path)

            docs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'docs')
            results = auditor.audit_directory(docs_dir)
            summary = auditor.generate_summary()

            return MaintenanceResult(
                operation='content_audit',
                success=True,
                duration=time.time() - start_time,
                details={
                    'files_audited': len(results),
                    'total_words': summary.total_words,
                    'average_quality': summary.average_quality,
                    'critical_issues': summary.critical_issues
                },
                timestamp=datetime.now()
            )

        except Exception as e:
            return MaintenanceResult(
                operation='content_audit',
                success=False,
                duration=time.time() - start_time,
                details={'error': str(e)},
                timestamp=datetime.now()
            )

    def _run_link_validation(self) -> MaintenanceResult:
        """Run link validation."""
        start_time = time.time()

        try:
            from validate_links import LinkValidator
            validator = LinkValidator(self.config_path)

            docs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'docs')
            results = validator.validate_directory(docs_dir, check_external=True)
            summary = validator.generate_summary(results)

            return MaintenanceResult(
                operation='link_validation',
                success=True,
                duration=time.time() - start_time,
                details={
                    'files_checked': len(results),
                    'broken_links': summary.broken_links,
                    'external_links': summary.external_links,
                    'internal_links': summary.internal_links
                },
                timestamp=datetime.now()
            )

        except Exception as e:
            return MaintenanceResult(
                operation='link_validation',
                success=False,
                duration=time.time() - start_time,
                details={'error': str(e)},
                timestamp=datetime.now()
            )

    def _run_style_validation(self) -> MaintenanceResult:
        """Run style validation."""
        start_time = time.time()

        try:
            from validate_style import StyleValidator
            validator = StyleValidator(self.config_path)

            docs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'docs')
            results = validator.validate_directory(docs_dir)
            summary = validator.generate_summary(results)

            return MaintenanceResult(
                operation='style_validation',
                success=True,
                duration=time.time() - start_time,
                details={
                    'files_checked': len(results),
                    'total_violations': summary.total_violations,
                    'average_score': summary.average_score,
                    'files_with_issues': summary.files_with_violations
                },
                timestamp=datetime.now()
            )

        except Exception as e:
            return MaintenanceResult(
                operation='style_validation',
                success=False,
                duration=time.time() - start_time,
                details={'error': str(e)},
                timestamp=datetime.now()
            )

    def _run_content_optimization(self) -> MaintenanceResult:
        """Run content optimization."""
        start_time = time.time()

        try:
            from optimize import ContentOptimizer
            optimizer = ContentOptimizer(self.config_path)

            docs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'docs')
            results = optimizer.optimize_directory(docs_dir)
            summary = optimizer.generate_summary(results)

            return MaintenanceResult(
                operation='content_optimization',
                success=True,
                duration=time.time() - start_time,
                details={
                    'files_processed': len(results),
                    'total_changes': summary.total_changes,
                    'files_modified': summary.files_modified,
                    'backups_created': len(summary.backup_files_created)
                },
                timestamp=datetime.now()
            )

        except Exception as e:
            return MaintenanceResult(
                operation='content_optimization',
                success=False,
                duration=time.time() - start_time,
                details={'error': str(e)},
                timestamp=datetime.now()
            )

    def _run_report_generation(self) -> MaintenanceResult:
        """Generate quality reports."""
        start_time = time.time()

        try:
            from report import ReportGenerator
            generator = ReportGenerator(self.config_path)

            report_data = generator.generate_comprehensive_report()

            # Generate multiple report formats
            dashboard_file = generator.generate_dashboard(report_data)
            summary_file = generator.generate_weekly_summary(report_data)

            return MaintenanceResult(
                operation='report_generation',
                success=True,
                duration=time.time() - start_time,
                details={
                    'dashboard_generated': bool(dashboard_file),
                    'summary_generated': bool(summary_file),
                    'quality_score': report_data.audit_summary.get('average_quality', 0)
                },
                timestamp=datetime.now()
            )

        except Exception as e:
            return MaintenanceResult(
                operation='report_generation',
                success=False,
                duration=time.time() - start_time,
                details={'error': str(e)},
                timestamp=datetime.now()
            )

    def _run_synchronization(self) -> MaintenanceResult:
        """Run synchronization."""
        start_time = time.time()

        try:
            from sync import DocumentationSync
            sync_manager = DocumentationSync(self.config_path)

            # Get pending changes
            status = sync_manager.get_sync_status()
            if status.pending_changes:
                result = sync_manager.sync_changes('automated_maintenance', status.pending_changes)

                return MaintenanceResult(
                    operation='synchronization',
                    success=result.success,
                    duration=time.time() - start_time,
                    details={
                        'files_synced': len(result.files_affected),
                        'sync_success': result.success
                    },
                    timestamp=datetime.now()
                )
            else:
                return MaintenanceResult(
                    operation='synchronization',
                    success=True,
                    duration=time.time() - start_time,
                    details={'message': 'No changes to synchronize'},
                    timestamp=datetime.now()
                )

        except Exception as e:
            return MaintenanceResult(
                operation='synchronization',
                success=False,
                duration=time.time() - start_time,
                details={'error': str(e)},
                timestamp=datetime.now()
            )

    def _generate_summary(self) -> Dict[str, Any]:
        """Generate overall maintenance summary."""
        successful_ops = sum(1 for r in self.results if r.success)
        total_ops = len(self.results)
        total_duration = sum(r.duration for r in self.results)

        # Aggregate key metrics
        total_files_processed = 0
        total_issues = 0
        quality_scores = []

        for result in self.results:
            if result.operation == 'content_audit':
                total_files_processed = max(total_files_processed, result.details.get('files_audited', 0))
                total_issues += result.details.get('critical_issues', 0)
                if 'average_quality' in result.details:
                    quality_scores.append(result.details['average_quality'])

            elif result.operation in ['link_validation', 'style_validation']:
                total_files_processed = max(total_files_processed, result.details.get('files_checked', 0))
                if result.operation == 'link_validation':
                    total_issues += result.details.get('broken_links', 0)
                else:
                    total_issues += result.details.get('total_violations', 0)

            elif result.operation == 'style_validation' and 'average_score' in result.details:
                quality_scores.append(result.details['average_score'])

        average_quality = sum(quality_scores) / len(quality_scores) if quality_scores else 0

        return {
            'operations_completed': successful_ops,
            'total_operations': total_ops,
            'success_rate': (successful_ops / total_ops * 100) if total_ops > 0 else 0,
            'total_duration': total_duration,
            'files_processed': total_files_processed,
            'total_issues': total_issues,
            'average_quality_score': average_quality,
            'maintenance_effectiveness': self._calculate_effectiveness(average_quality, total_issues)
        }

    def _calculate_effectiveness(self, quality_score: float, issues: int) -> str:
        """Calculate maintenance effectiveness rating."""
        if quality_score >= 90 and issues == 0:
            return 'excellent'
        elif quality_score >= 80 and issues <= 5:
            return 'good'
        elif quality_score >= 70 and issues <= 15:
            return 'fair'
        else:
            return 'needs_attention'

    def _save_report(self, report: MaintenanceReport):
        """Save detailed maintenance report."""
        reports_dir = os.path.join(os.path.dirname(__file__), 'reports')
        os.makedirs(reports_dir, exist_ok=True)

        report_file = os.path.join(reports_dir, f'maintenance_{self.session_id}.json')

        with open(report_file, 'w') as f:
            # Convert dataclasses to dicts for JSON serialization
            report_dict = {
                'session_id': report.session_id,
                'timestamp': report.timestamp.isoformat(),
                'operations_run': [asdict(op) for op in report.operations_run],
                'overall_success': report.overall_success,
                'total_duration': report.total_duration,
                'summary': report.summary
            }
            json.dump(report_dict, f, indent=2, default=str)

def main():
    parser = argparse.ArgumentParser(description='Documentation Maintenance Orchestrator')
    parser.add_argument('--comprehensive', action='store_true',
                       help='Run comprehensive maintenance suite')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--output', '-o', help='Output report file')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be done without making changes')

    args = parser.parse_args()

    maintainer = DocumentationMaintainer(args.config)

    if args.comprehensive or not any([args.comprehensive]):
        # Default to comprehensive maintenance
        report = maintainer.run_comprehensive_maintenance()

        # Print results
        print("\n" + "="*60)
        print("📋 MAINTENANCE COMPLETION REPORT")
        print("="*60)
        print(f"🆔 Session ID: {report.session_id}")
        print(f"📅 Completed: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print(".1f"
        success_rate = report.summary['success_rate']
        print(".1f"
        # Overall status
        if report.overall_success:
            print("✅ Overall Status: SUCCESS")
        else:
            print("❌ Overall Status: ISSUES DETECTED")

        print("
📊 Summary:"        print(f"  📁 Files Processed: {report.summary['files_processed']}")
        print(f"  🚨 Total Issues: {report.summary['total_issues']}")
        print(".1f"        print(f"  📈 Effectiveness: {report.summary['maintenance_effectiveness'].title()}")

        # Operation results
        print("
🔧 Operations Completed:"        for result in report.operations_run:
            status = "✅" if result.success else "❌"
            duration = ".1f"            details = result.details

            print(f"  {status} {result.operation.replace('_', ' ').title()} ({duration}s)")

            if args.verbose and details:
                for key, value in details.items():
                    if key != 'error':
                        print(f"    {key}: {value}")

        # Recommendations
        effectiveness = report.summary['maintenance_effectiveness']
        if effectiveness in ['needs_attention', 'fair']:
            print("
💡 Recommendations:"            if report.summary['total_issues'] > 10:
                print("  - Address high number of issues across documentation")
            if report.summary['average_quality_score'] < 70:
                print("  - Focus on improving content quality and structure")
            print("  - Consider running maintenance more frequently")
        elif effectiveness == 'good':
            print("
✅ Good maintenance results - continue regular upkeep"        else:
            print("
🎉 Excellent maintenance results - documentation is in great shape!"
        # Save report if requested
        if args.output:
            maintainer._save_report(report)
            print(f"\n💾 Detailed report saved to: {args.output}")

if __name__ == '__main__':
    main()
#!/usr/bin/env python3
"""Documentation Quality Assurance Reporting System.

Generates comprehensive reports, dashboards, and analytics for documentation maintenance.
Provides visualization and tracking of quality metrics over time.
"""

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

try:
    import matplotlib.pyplot as plt
    import seaborn as sns

    HAS_VISUALIZATION = True
except ImportError:
    HAS_VISUALIZATION = False

# Add parent directory to path for imports
sys.path.insert(0, Path(Path(Path(__file__).resolve()).parent).parent)


@dataclass
class ReportData:
    """Container for all report data."""

    timestamp: datetime
    audit_summary: dict[str, Any]
    validation_summary: dict[str, Any]
    style_summary: dict[str, Any]
    trends: dict[str, Any]
    recommendations: list[dict[str, Any]]


@dataclass
class QualityMetrics:
    """Quality metrics for documentation health."""

    overall_score: float
    content_health: float
    link_health: float
    style_consistency: float
    accessibility: float
    trends_direction: str  # 'improving', 'stable', 'declining'


class ReportGenerator:
    """Main report generation class."""

    def __init__(self, config_path: str | None = None) -> None:
        self.config = self._load_config(config_path)
        self.reports_dir = os.path.join(Path(__file__).parent, "reports")
        Path(self.reports_dir).mkdir(exist_ok=True, parents=True)

    def _load_config(self, config_path: str | None = None) -> dict[str, Any]:
        """Load configuration."""
        default_config = {
            "reporting": {
                "output_formats": ["html", "json", "markdown"],
                "include_charts": True,
                "chart_style": "seaborn",
                "metrics_history_days": 30,
                "dashboard_template": "default",
            },
            "thresholds": {
                "excellent_score": 90,
                "good_score": 70,
                "fair_score": 50,
                "critical_issues_threshold": 10,
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

    def generate_comprehensive_report(
        self,
        audit_file: str | None = None,
        validation_file: str | None = None,
        style_file: str | None = None,
    ) -> ReportData:
        """Generate comprehensive report from audit results."""
        # Load data from files or run fresh audits
        audit_data = self._load_audit_data(audit_file)
        validation_data = self._load_validation_data(validation_file)
        style_data = self._load_style_data(style_file)

        # Calculate trends
        trends = self._calculate_trends()

        # Generate recommendations
        recommendations = self._generate_recommendations(
            audit_data, validation_data, style_data
        )

        return ReportData(
            timestamp=datetime.now(UTC),
            audit_summary=audit_data.get("summary", {}),
            validation_summary=validation_data.get("summary", {}),
            style_summary=style_data.get("summary", {}),
            trends=trends,
            recommendations=recommendations,
        )

    def _load_audit_data(self, audit_file: str | None) -> dict[str, Any]:
        """Load audit data."""
        if audit_file and Path(audit_file).exists():
            with Path(audit_file).open(encoding="utf-8") as f:
                return json.load(f)
        return self._run_quick_audit()

    def _load_validation_data(self, validation_file: str | None) -> dict[str, Any]:
        """Load validation data."""
        if validation_file and Path(validation_file).exists():
            with Path(validation_file).open(encoding="utf-8") as f:
                return json.load(f)
        return self._run_quick_validation()

    def _load_style_data(self, style_file: str | None) -> dict[str, Any]:
        """Load style data."""
        if style_file and Path(style_file).exists():
            with Path(style_file).open(encoding="utf-8") as f:
                return json.load(f)
        return self._run_quick_style_check()

    def _run_quick_audit(self) -> dict[str, Any]:
        """Run a quick audit for basic metrics."""
        # Import here to avoid circular imports
        sys.path.insert(0, Path(__file__).parent)
        from audit import DocumentationAuditor

        auditor = DocumentationAuditor()
        results = auditor.audit_directory(
            os.path.join(Path(__file__).parent, ".."), recursive=False
        )
        summary = auditor.generate_summary()

        return {
            "summary": asdict(summary),
            "results": [asdict(r) for r in results[:10]],  # Limit for quick audit
        }

    def _run_quick_validation(self) -> dict[str, Any]:
        """Run quick link validation."""
        from validate_links import LinkValidator

        validator = LinkValidator()
        results = validator.validate_directory(
            os.path.join(Path(__file__).parent, ".."),
            check_external=False,  # Quick mode
        )
        summary = validator.generate_summary(results)

        return {"summary": asdict(summary), "results": [asdict(r) for r in results[:5]]}

    def _run_quick_style_check(self) -> dict[str, Any]:
        """Run quick style validation."""
        from validate_style import StyleValidator

        validator = StyleValidator()
        results = validator.validate_directory(
            os.path.join(Path(__file__).parent, "..")
        )
        summary = validator.generate_summary(results)

        return {"summary": asdict(summary), "results": [asdict(r) for r in results[:5]]}

    def _calculate_trends(self) -> dict[str, Any]:
        """Calculate quality trends from historical data."""
        # Look for historical reports
        history_dir = os.path.join(self.reports_dir, "history")
        if not Path(history_dir).exists():
            return {
                "available": False,
                "message": "No historical data available for trend analysis",
            }

        # Load recent reports
        recent_reports = []
        for file in sorted(os.listdir(history_dir))[-7:]:  # Last 7 reports
            if file.endswith(".json"):
                try:
                    with Path(os.path.join(history_dir, file)).open(
                        encoding="utf-8"
                    ) as f:
                        report = json.load(f)
                        recent_reports.append(report)
                except:
                    continue

        if len(recent_reports) < 2:
            return {
                "available": False,
                "message": f"Need at least 2 reports for trends, found {len(recent_reports)}",
            }

        # Calculate trends
        scores = [
            r.get("quality_metrics", {}).get("overall_score", 0) for r in recent_reports
        ]
        trend_direction = "stable"

        if len(scores) >= 3:
            recent_avg = sum(scores[-3:]) / 3
            older_avg = sum(scores[:-3]) / max(1, len(scores[:-3]))

            if recent_avg > older_avg + 5:
                trend_direction = "improving"
            elif recent_avg < older_avg - 5:
                trend_direction = "declining"

        return {
            "available": True,
            "direction": trend_direction,
            "recent_scores": scores[-5:],
            "average_score": sum(scores) / len(scores),
            "reports_analyzed": len(recent_reports),
        }

    def _generate_recommendations(
        self, audit_data: dict, validation_data: dict, style_data: dict
    ) -> list[dict[str, Any]]:
        """Generate actionable recommendations."""
        recommendations = []

        # Audit-based recommendations
        audit_summary = audit_data.get("summary", {})
        if audit_summary.get("critical_issues", 0) > 0:
            recommendations.append({
                "priority": "high",
                "category": "content",
                "title": "Address Critical Content Issues",
                "description": f"{audit_summary['critical_issues']} critical content issues require immediate attention",
                "actions": [
                    "Review files with quality score < 50",
                    "Update outdated content (>90 days old)",
                    "Fix broken internal references",
                ],
            })

        # Link validation recommendations
        validation_summary = validation_data.get("summary", {})
        broken_links = validation_summary.get("broken_links", 0)
        if broken_links > 10:
            recommendations.append({
                "priority": "medium",
                "category": "links",
                "title": "Fix Broken Links",
                "description": f"{broken_links} broken links detected across documentation",
                "actions": [
                    "Update or remove broken external links",
                    "Fix incorrect internal references",
                    "Review most broken domains",
                ],
            })

        # Style recommendations
        style_summary = style_data.get("summary", {})
        style_score = style_summary.get("average_score", 100)
        if style_score < 80:
            recommendations.append({
                "priority": "low",
                "category": "style",
                "title": "Improve Style Consistency",
                "description": f"Average style score of {style_score:.1f}/100 indicates formatting issues",
                "actions": [
                    "Fix heading hierarchy violations",
                    "Add language specifications to code blocks",
                    "Remove trailing whitespace",
                ],
            })

        # Default recommendations
        if not recommendations:
            recommendations.append({
                "priority": "info",
                "category": "maintenance",
                "title": "Schedule Regular Maintenance",
                "description": "Documentation quality is good, continue regular maintenance",
                "actions": [
                    "Run weekly comprehensive audits",
                    "Monitor link health monthly",
                    "Review content freshness quarterly",
                ],
            })

        return recommendations

    def generate_dashboard(
        self, report_data: ReportData, output_file: str = "dashboard.html"
    ) -> str:
        """Generate HTML dashboard (requires visualization libraries)."""
        if not HAS_VISUALIZATION:
            return ""

        template = self._get_dashboard_template()

        # Calculate quality metrics
        metrics = self._calculate_quality_metrics(report_data)

        # Prepare data for template
        template_data = {
            "timestamp": report_data.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "overall_score": metrics.overall_score,
            "content_health": metrics.content_health,
            "link_health": metrics.link_health,
            "style_consistency": metrics.style_consistency,
            "accessibility": metrics.accessibility,
            "trends_direction": metrics.trends_direction,
            "audit_summary": report_data.audit_summary,
            "validation_summary": report_data.validation_summary,
            "style_summary": report_data.style_summary,
            "recommendations": report_data.recommendations,
            "trends": report_data.trends,
        }

        # Render template
        dashboard_html = template.format(**template_data)

        Path(self.reports_dir).mkdir(exist_ok=True, parents=True)
        output_path = os.path.join(self.reports_dir, output_file)
        with Path(output_path).open("w", encoding="utf-8") as f:
            f.write(dashboard_html)

        return output_path

    def _calculate_quality_metrics(self, report_data: ReportData) -> QualityMetrics:
        """Calculate overall quality metrics."""
        audit_score = report_data.audit_summary.get("average_quality", 100)
        link_broken = report_data.validation_summary.get("broken_links", 0)
        link_total = report_data.validation_summary.get("total_links", 1)
        style_score = report_data.style_summary.get("average_score", 100)

        # Content health (60% weight on audit)
        content_health = audit_score * 0.6

        # Link health (inverse of broken link ratio)
        link_health = (
            max(0, 100 - (link_broken / link_total * 100)) if link_total > 0 else 100
        )

        # Style consistency (40% weight on style)
        style_consistency = style_score * 0.4

        # Accessibility (estimated from style and links)
        accessibility = (style_score + link_health) / 2

        # Overall score
        overall_score = (
            content_health * 0.4
            + link_health * 0.3
            + style_consistency * 0.2
            + accessibility * 0.1
        )

        # Trends direction
        trends_direction = report_data.trends.get("direction", "stable")

        return QualityMetrics(
            overall_score=round(overall_score, 1),
            content_health=round(content_health, 1),
            link_health=round(link_health, 1),
            style_consistency=round(style_consistency, 1),
            accessibility=round(accessibility, 1),
            trends_direction=trends_direction,
        )

    def _get_dashboard_template(self) -> str:
        """Get HTML dashboard template."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Documentation Quality Dashboard</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .score {{
            font-size: 48px;
            font-weight: bold;
            margin: 10px 0;
        }}
        .status {{
            font-size: 18px;
            opacity: 0.9;
        }}
        .metrics {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
        }}
        .metric {{
            text-align: center;
            padding: 20px;
            border-radius: 8px;
            background: #f8f9fa;
        }}
        .metric-value {{
            font-size: 32px;
            font-weight: bold;
            color: #495057;
        }}
        .metric-label {{
            font-size: 14px;
            color: #6c757d;
            margin-top: 5px;
        }}
        .recommendations {{
            padding: 30px;
            border-top: 1px solid #e9ecef;
        }}
        .recommendation {{
            margin-bottom: 20px;
            padding: 15px;
            border-radius: 6px;
            border-left: 4px solid;
        }}
        .priority-high {{ border-color: #dc3545; background: #f8d7da; }}
        .priority-medium {{ border-color: #ffc107; background: #fff3cd; }}
        .priority-low {{ border-color: #28a745; background: #d4edda; }}
        .priority-info {{ border-color: #17a2b8; background: #d1ecf1; }}
        .timestamp {{
            text-align: center;
            color: #6c757d;
            font-size: 14px;
            margin-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Documentation Quality Dashboard</h1>
            <div class="score">{overall_score}/100</div>
            <div class="status">Overall Quality Score</div>
            <div class="timestamp">Generated: {timestamp}</div>
        </div>

        <div class="metrics">
            <div class="metric">
                <div class="metric-value">{content_health}</div>
                <div class="metric-label">Content Health</div>
            </div>
            <div class="metric">
                <div class="metric-value">{link_health}</div>
                <div class="metric-label">Link Health</div>
            </div>
            <div class="metric">
                <div class="metric-value">{style_consistency}</div>
                <div class="metric-label">Style Consistency</div>
            </div>
            <div class="metric">
                <div class="metric-value">{accessibility}</div>
                <div class="metric-label">Accessibility</div>
            </div>
        </div>

        <div class="recommendations">
            <h2>🎯 Recommendations</h2>
            {"".join([f'''
            <div class="recommendation priority-{rec["priority"]}">
                <h4>{rec["title"]}</h4>
                <p>{rec["description"]}</p>
                <ul>
                    {"".join([f"<li>{action}</li>" for action in rec["actions"]])}
                </ul>
            </div>
            ''' for rec in recommendations])}
        </div>
    </div>
</body>
</html>"""

    def generate_weekly_summary(
        self, report_data: ReportData, output_file: str = "weekly-summary.md"
    ) -> str:
        """Generate markdown weekly summary."""
        Path(self.reports_dir).mkdir(exist_ok=True, parents=True)
        metrics = self._calculate_quality_metrics(report_data)

        summary = f"""# 📊 Weekly Documentation Quality Summary

**Generated:** {report_data.timestamp.strftime("%Y-%m-%d %H:%M:%S")}

## 🎯 Overall Quality Score: {metrics.overall_score}/100

### Quality Breakdown
- **Content Health:** {metrics.content_health}/100
- **Link Health:** {metrics.link_health}/100
- **Style Consistency:** {metrics.style_consistency}/100
- **Accessibility:** {metrics.accessibility}/100

### Trends
- **Direction:** {metrics.trends_direction.title()}
- **Recent Scores:** {", ".join(map(str, report_data.trends.get("recent_scores", [])))}

## 📈 Key Metrics

### Content Quality
- **Files Audited:** {report_data.audit_summary.get("total_files", 0)}
- **Total Words:** {report_data.audit_summary.get("total_words", 0):,}
- **Average Age:** {report_data.audit_summary.get("average_age", 0):.1f} days
- **Critical Issues:** {report_data.audit_summary.get("critical_issues", 0)}

### Link Health
- **Total Links:** {report_data.validation_summary.get("total_links", 0)}
- **Broken Links:** {report_data.validation_summary.get("broken_links", 0)}
- **External Links:** {report_data.validation_summary.get("external_links", 0)}
- **Internal Links:** {report_data.validation_summary.get("internal_links", 0)}

### Style Consistency
- **Files Checked:** {report_data.style_summary.get("total_files", 0)}
- **Total Violations:** {report_data.style_summary.get("total_violations", 0)}
- **Average Score:** {report_data.style_summary.get("average_score", 0):.1f}/100
- **Files with Issues:** {report_data.style_summary.get("files_with_violations", 0)}

## 🎯 Priority Actions

"""

        # Add recommendations
        for rec in report_data.recommendations:
            summary += f"""### {rec["title"]} ({rec["priority"].title()} Priority)
{rec["description"]}

**Actions:**
{"".join([f"- {action}\\n" for action in rec["actions"]])}

"""

        output_path = os.path.join(self.reports_dir, output_file)
        with Path(output_path).open("w", encoding="utf-8") as f:
            f.write(summary)

        return output_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Documentation Quality Assurance Reporting System"
    )
    parser.add_argument("--audit-file", help="Path to audit results JSON file")
    parser.add_argument(
        "--validation-file", help="Path to validation results JSON file"
    )
    parser.add_argument("--style-file", help="Path to style results JSON file")
    parser.add_argument(
        "--generate-dashboard", action="store_true", help="Generate HTML dashboard"
    )
    parser.add_argument(
        "--weekly-summary", action="store_true", help="Generate weekly markdown summary"
    )
    parser.add_argument(
        "--monthly-report", action="store_true", help="Generate detailed monthly report"
    )
    parser.add_argument(
        "--output-dir", default="reports", help="Output directory for reports"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    generator = ReportGenerator()
    generator.reports_dir = args.output_dir
    Path(generator.reports_dir).mkdir(exist_ok=True, parents=True)

    if args.verbose:
        pass

    # Generate comprehensive report
    report_data = generator.generate_comprehensive_report(
        args.audit_file, args.validation_file, args.style_file
    )

    generated_files = []

    if args.generate_dashboard:
        dashboard_file = generator.generate_dashboard(report_data)
        generated_files.append(("Dashboard", dashboard_file))

    if args.weekly_summary:
        summary_file = generator.generate_weekly_summary(report_data)
        generated_files.append(("Weekly Summary", summary_file))

    if args.monthly_report:
        # Monthly report would be more detailed
        monthly_file = generator.generate_dashboard(report_data, "monthly-report.html")
        generated_files.append(("Monthly Report", monthly_file))

    # If no specific report requested, generate dashboard
    if not any([args.generate_dashboard, args.weekly_summary, args.monthly_report]):
        dashboard_file = generator.generate_dashboard(report_data)
        summary_file = generator.generate_weekly_summary(report_data)
        generated_files.extend([
            ("Dashboard", dashboard_file),
            ("Weekly Summary", summary_file),
        ])

    # Calculate and display quality score
    generator._calculate_quality_metrics(report_data)

    if generated_files:
        for _name, _path in generated_files:
            pass


if __name__ == "__main__":
    main()

"""Documentation Content Quality Audit System.

Comprehensive auditing tool for documentation quality, freshness, and completeness.
Performs multi-dimensional analysis of documentation content.
"""

import argparse
import json
import operator
import os
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TypedDict

import yaml
from flext_core import FlextCore

# Constants for audit configuration
MAX_AGE_DAYS: int = FlextCore.Constants.Validation.MAX_AGE
EXCELLENT_QUALITY_SCORE: float = FlextCore.Constants.Validation.MAX_PERCENTAGE - 10
GOOD_QUALITY_SCORE: float = FlextCore.Constants.Validation.MAX_PERCENTAGE - 20
FAIR_QUALITY_SCORE: float = FlextCore.Constants.Validation.MAX_PERCENTAGE - 30
EXCELLENT_FRESHNESS_DAYS: int = MAX_AGE_DAYS
LONG_PARAGRAPH_WORD_LIMIT: int = FlextCore.Constants.Validation.PREVIEW_LENGTH * 3


# Type definitions
class IssueInfo(TypedDict):
    """Information about a documentation issue."""

    type: str
    pattern: str | None
    count: int | None
    message: str
    link_text: str | None
    url: str | None
    line_number: int | None
    severity: str | None


class WarningInfo(TypedDict):
    """Information about a documentation warning."""

    type: str
    url: str | None
    alt_text: str | None
    message: str
    line_number: int | None


class SuggestionInfo(TypedDict):
    """Information about a documentation suggestion."""

    type: str
    message: str
    improvement: str | None
    line_number: int | None


class AuditThresholds(TypedDict):
    """Audit thresholds configuration."""

    min_word_count: int
    max_age_days: int
    min_quality_score: int
    min_completeness_score: int


class AuditSettings(TypedDict):
    """Audit settings configuration."""

    include_patterns: list[str]
    exclude_patterns: list[str]
    thresholds: AuditThresholds


class ContentSettings(TypedDict):
    """Content settings configuration."""

    required_sections: list[str]
    prohibited_patterns: list[str]


class AuditConfig(TypedDict):
    """Configuration for documentation audit."""

    audit: AuditSettings
    content: ContentSettings


@dataclass
class AuditResult:
    """Result of a single file audit."""

    file_path: str
    file_size: int
    word_count: int
    last_modified: datetime
    age_days: int
    freshness_score: int
    completeness_score: int
    structure_score: int
    quality_score: int
    issues: list[IssueInfo]
    warnings: list[WarningInfo]
    suggestions: list[SuggestionInfo]


@dataclass
class AuditSummary:
    """Summary of audit results."""

    total_files: int
    total_words: int
    average_age: float
    average_quality: float
    total_issues: int
    total_warnings: int
    critical_issues: int
    files_by_quality: dict[str, int]
    issues_by_category: dict[str, int]
    oldest_files: list[tuple[str, int]]
    newest_files: list[tuple[str, int]]


class DocumentationAuditor:
    """Main documentation auditing class."""

    def __init__(self, config_path: str | None = None) -> None:
        """Initialize documentation auditor with optional configuration file.

        Args:
            config_path: Path to YAML configuration file, or None for defaults.

        """
        self.config: AuditConfig = self._load_config(config_path)
        self.results: list[AuditResult] = []
        self.summary: AuditSummary | None = None

    def _load_config(self, config_path: str | None) -> AuditConfig:
        """Load configuration from YAML file."""
        default_config = {
            "audit": {
                "include_patterns": ["*.md", "*.mdx"],
                "exclude_patterns": ["node_modules/**", ".git/**", "**/.*"],
                "thresholds": {
                    "min_word_count": 100,
                    "max_age_days": 90,
                    "min_quality_score": 70,
                    "min_completeness_score": 60,
                },
            },
            "content": {
                "required_sections": ["Overview", "Installation"],
                "prohibited_patterns": ["TODO", "FIXME", "HACK"],
            },
        }

        if config_path and Path(config_path).exists():
            with Path(config_path).open(encoding="utf-8") as f:
                user_config = yaml.safe_load(f)
                # Merge configs
                for key, value in user_config.items():
                    if key in default_config:
                        default_config[key].update(value)
                    else:
                        default_config[key] = value

        return default_config

    def audit_file(self, file_path: str) -> AuditResult:
        """Audit a single documentation file."""
        try:
            with Path(file_path).open(encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            return AuditResult(
                file_path=file_path,
                file_size=0,
                word_count=0,
                last_modified=datetime.now(UTC),
                age_days=0,
                freshness_score=0,
                completeness_score=0,
                structure_score=0,
                quality_score=0,
                issues=[
                    {
                        "type": "error",
                        "pattern": None,
                        "count": None,
                        "message": f"Failed to read file: {e}",
                        "link_text": None,
                        "url": None,
                        "line_number": None,
                        "severity": "error",
                    }
                ],
                warnings=[],
                suggestions=[],
            )

        # Get file metadata
        path_obj = Path(file_path)
        stat = path_obj.stat()
        last_modified = datetime.fromtimestamp(stat.st_mtime, tz=UTC)
        age_days = (datetime.now(UTC) - last_modified).days
        file_size = stat.st_size

        # Analyze content
        word_count = len(content.split())
        issues = []
        warnings = []
        suggestions = []

        # Freshness analysis
        freshness_score = self._calculate_freshness_score(age_days)

        # Completeness analysis
        completeness_score = self._calculate_completeness_score(content, word_count)

        # Structure analysis
        structure_score = self._calculate_structure_score(content)

        # Quality analysis
        quality_score = self._calculate_quality_score(
            freshness_score, completeness_score, structure_score
        )

        # Issue detection
        self._detect_issues(content, file_path, issues, warnings, suggestions)

        return AuditResult(
            file_path=file_path,
            file_size=file_size,
            word_count=word_count,
            last_modified=last_modified,
            age_days=age_days,
            freshness_score=freshness_score,
            completeness_score=completeness_score,
            structure_score=structure_score,
            quality_score=quality_score,
            issues=issues,
            warnings=warnings,
            suggestions=suggestions,
        )

    def _calculate_freshness_score(self, age_days: int) -> int:
        """Calculate freshness score based on file age."""
        max_age = self.config["audit"]["thresholds"]["max_age_days"]
        if age_days <= EXCELLENT_FRESHNESS_DAYS:
            return 100
        if age_days <= max_age:
            return int(
                100
                * (
                    1
                    - (age_days - EXCELLENT_FRESHNESS_DAYS)
                    / (max_age - EXCELLENT_FRESHNESS_DAYS)
                )
            )
        return max(0, int(50 * (1 - (age_days - max_age) / max_age)))

    def _calculate_completeness_score(self, content: str, word_count: int) -> int:
        """Calculate completeness score based on content analysis."""
        score = 0

        # Word count check
        min_words = self.config["audit"]["thresholds"]["min_word_count"]
        if word_count >= min_words:
            score += 40
        elif word_count >= min_words * 0.5:
            score += 20

        # Required sections check
        required_sections = self.config["content"]["required_sections"]
        found_sections = 0
        for section in required_sections:
            if re.search(
                rf"^#+\s*{re.escape(section)}", content, re.MULTILINE | re.IGNORECASE
            ):
                found_sections += 1

        section_score = (found_sections / len(required_sections)) * 60
        score += section_score

        return min(100, int(score))

    def _calculate_structure_score(self, content: str) -> int:
        """Calculate structure score based on markdown formatting."""
        score = 100

        # Check for proper heading hierarchy
        lines = content.split("\n")
        headings = []
        for line in lines:
            if line.startswith("#"):
                level = len(line.split()[0]) if line.split() else 0
                headings.append(level)

        # Check hierarchy (should not skip levels)
        for i in range(1, len(headings)):
            if headings[i] > headings[i - 1] + 1:
                score -= 20

        # Check for code blocks (should have language specified)
        code_blocks = re.findall(r"```(\w+)?", content)
        if code_blocks:
            unspecified = code_blocks.count("")
            if unspecified > 0:
                score -= min(MAX_AGE_DAYS, unspecified * 10)

        # Check for broken links (basic check)
        links = re.findall(r"\[([^\]]+)\]\(([^)]+)\)", content)
        broken_count = 0
        for _text, url in links:
            if not url or url.startswith("#") or "http" in url:
                continue
            # Check if relative link exists
            if not (Path().parent / url).exists():
                broken_count += 1

        score -= min(50, broken_count * 15)

        return max(0, score)

    def _calculate_quality_score(
        self, freshness: int, completeness: int, structure: int
    ) -> int:
        """Calculate overall quality score."""
        return int((freshness * 0.3) + (completeness * 0.4) + (structure * 0.3))

    def _detect_issues(
        self,
        content: str,
        file_path: str,
        issues: list[IssueInfo],
        warnings: list[WarningInfo],
        suggestions: list[SuggestionInfo],
    ) -> None:
        """Detect various issues in the content."""
        # Check for prohibited patterns
        prohibited = self.config["content"]["prohibited_patterns"]
        for pattern in prohibited:
            matches = re.findall(rf"\b{re.escape(pattern)}\b", content, re.IGNORECASE)
            if matches:
                issues.append({
                    "type": "prohibited_pattern",
                    "pattern": pattern,
                    "count": len(matches),
                    "message": f'Found {len(matches)} instances of prohibited pattern "{pattern}"',
                    "link_text": None,
                    "url": None,
                    "line_number": None,
                    "severity": "warning",
                })

        # Check for broken internal links
        internal_links = re.findall(r"\[([^\]]+)\]\(([^)]+)\)", content)
        for text, url in internal_links:
            if url.startswith(("http", "#")):
                continue
            full_path = Path(file_path).parent / url
            if not Path(full_path).exists():
                issues.append({
                    "type": "broken_link",
                    "pattern": None,
                    "count": None,
                    "message": f"Broken internal link: {url}",
                    "link_text": text,
                    "url": url,
                    "line_number": None,
                    "severity": "error",
                })

        # Check for images without alt text
        images = re.findall(r"!\[([^\]]*)\]\(([^)]+)\)", content)
        for alt_text, url in images:
            if not alt_text.strip():
                warnings.append({
                    "type": "missing_alt_text",
                    "url": url,
                    "alt_text": None,
                    "message": f"Image missing alt text: {url}",
                    "line_number": None,
                })

        # Check for long paragraphs
        paragraphs = re.split(r"\n\s*\n", content)
        for para in paragraphs:
            words = len(para.split())
            if words > LONG_PARAGRAPH_WORD_LIMIT:  # Very long paragraph
                suggestions.append({
                    "type": "long_paragraph",
                    "improvement": f"Consider breaking up long paragraph ({words} words)",
                    "line_number": None,
                    "message": f"Consider breaking up long paragraph ({words} words)",
                })

    def audit_directory(
        self, directory: str, *, recursive: bool = True
    ) -> list[AuditResult]:
        """Audit all documentation files in a directory."""
        results = []

        for root, dirs, files in os.walk(directory):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if not self._is_excluded(str(Path(root) / d))]

            for file in files:
                file_path = Path(root) / file
                if self._should_audit_file(str(file_path)):
                    result = self.audit_file(str(file_path))
                    results.append(result)

            if not recursive:
                break

        self.results = results
        return results

    def _should_audit_file(self, file_path: str) -> bool:
        """Check if file should be audited."""
        if self._is_excluded(file_path):
            return False

        # Check include patterns
        for pattern in self.config["audit"]["include_patterns"]:
            if file_path.endswith(pattern.replace("*", "")):
                return True

        return False

    def _is_excluded(self, path: str) -> bool:
        """Check if path is excluded."""
        for pattern in self.config["audit"]["exclude_patterns"]:
            if pattern in path or path.startswith(pattern):
                return True
        return False

    def generate_summary(self) -> AuditSummary:
        """Generate summary of audit results."""
        if not self.results:
            return AuditSummary(
                total_files=0,
                total_words=0,
                average_age=0,
                average_quality=0,
                total_issues=0,
                total_warnings=0,
                critical_issues=0,
                files_by_quality={},
                issues_by_category={},
                oldest_files=[],
                newest_files=[],
            )

        total_files = len(self.results)
        total_words = sum(r.word_count for r in self.results)
        average_age = sum(r.age_days for r in self.results) / total_files
        average_quality = sum(r.quality_score for r in self.results) / total_files

        total_issues = sum(len(r.issues) for r in self.results)
        total_warnings = sum(len(r.warnings) for r in self.results)
        critical_issues = sum(
            1 for r in self.results if r.quality_score < FAIR_QUALITY_SCORE
        )

        # Quality distribution
        quality_ranges = {"excellent": 0, "good": 0, "fair": 0, "poor": 0}
        for result in self.results:
            if result.quality_score >= EXCELLENT_QUALITY_SCORE:
                quality_ranges["excellent"] += 1
            elif result.quality_score >= GOOD_QUALITY_SCORE:
                quality_ranges["good"] += 1
            elif result.quality_score >= FAIR_QUALITY_SCORE:
                quality_ranges["fair"] += 1
            else:
                quality_ranges["poor"] += 1

        # Issues by category
        issues_by_category = {}
        for result in self.results:
            for issue in result.issues:
                category = issue.get("type", "unknown")
                issues_by_category[category] = issues_by_category.get(category, 0) + 1

        # Oldest and newest files
        sorted_by_age = sorted(self.results, key=lambda r: r.age_days, reverse=True)
        oldest_files = [(r.file_path, r.age_days) for r in sorted_by_age[:5]]
        newest_files = [(r.file_path, r.age_days) for r in sorted_by_age[-5:]]

        self.summary = AuditSummary(
            total_files=total_files,
            total_words=total_words,
            average_age=average_age,
            average_quality=average_quality,
            total_issues=total_issues,
            total_warnings=total_warnings,
            critical_issues=critical_issues,
            files_by_quality=quality_ranges,
            issues_by_category=issues_by_category,
            oldest_files=oldest_files,
            newest_files=newest_files,
        )

        return self.summary

    def save_results(self, output_file: str, output_format: str = "json") -> None:
        """Save audit results to file."""
        if output_format == "json":
            data = {
                "timestamp": datetime.now(UTC).isoformat(),
                "summary": asdict(self.summary) if self.summary else None,
                "results": [asdict(r) for r in self.results],
            }
            with Path(output_file).open("w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
        elif format == "yaml":
            data = {
                "timestamp": datetime.now(UTC).isoformat(),
                "summary": asdict(self.summary) if self.summary else None,
                "results": [asdict(r) for r in self.results],
            }
            with Path(output_file).open("w", encoding="utf-8") as f:
                yaml.dump(data, f, default_flow_style=False)


def main() -> None:
    """Main entry point for the documentation audit system."""
    parser = argparse.ArgumentParser(
        description="Documentation Content Quality Audit System"
    )
    parser.add_argument("directory", help="Directory to audit")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--output", "-o", help="Output file path")
    parser.add_argument(
        "--format", choices=["json", "yaml"], default="json", help="Output format"
    )
    parser.add_argument(
        "--comprehensive", action="store_true", help="Run comprehensive audit"
    )
    parser.add_argument("--quick", action="store_true", help="Run quick audit")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    auditor = DocumentationAuditor(args.config)

    if args.verbose:
        pass

    auditor.audit_directory(args.directory, recursive=True)

    if args.verbose:
        pass

    summary = auditor.generate_summary()

    if args.output:
        auditor.save_results(args.output, args.format)

    # Print summary

    for _quality, _count in summary.files_by_quality.items():
        pass

    for _category, _count in sorted(
        summary.issues_by_category.items(), key=operator.itemgetter(1), reverse=True
    )[:5]:
        pass

    if summary.oldest_files:
        for _path, _age in summary.oldest_files[:3]:
            pass

    # Health score
    min(100, max(0, int(summary.average_quality - (summary.total_issues * 2))))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Documentation Content Quality Audit System

Comprehensive auditing tool for documentation quality, freshness, and completeness.
Performs multi-dimensional analysis of documentation content.
"""

import os
import sys
import time
import yaml
import json
import argparse
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import re
import subprocess

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
    issues: List[Dict[str, Any]]
    warnings: List[Dict[str, Any]]
    suggestions: List[Dict[str, Any]]

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
    files_by_quality: Dict[str, int]
    issues_by_category: Dict[str, int]
    oldest_files: List[Tuple[str, int]]
    newest_files: List[Tuple[str, int]]

class DocumentationAuditor:
    """Main documentation auditing class."""

    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.results: List[AuditResult] = []
        self.summary: Optional[AuditSummary] = None

    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        default_config = {
            'audit': {
                'include_patterns': ['*.md', '*.mdx'],
                'exclude_patterns': ['node_modules/**', '.git/**', '**/.*'],
                'thresholds': {
                    'min_word_count': 100,
                    'max_age_days': 90,
                    'min_quality_score': 70,
                    'min_completeness_score': 60
                }
            },
            'content': {
                'required_sections': ['Overview', 'Installation'],
                'prohibited_patterns': ['TODO', 'FIXME', 'HACK']
            }
        }

        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
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
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            return AuditResult(
                file_path=file_path,
                file_size=0,
                word_count=0,
                last_modified=datetime.now(),
                age_days=0,
                freshness_score=0,
                completeness_score=0,
                structure_score=0,
                quality_score=0,
                issues=[{'type': 'error', 'message': f'Failed to read file: {e}'}],
                warnings=[],
                suggestions=[]
            )

        # Get file metadata
        stat = os.stat(file_path)
        last_modified = datetime.fromtimestamp(stat.st_mtime)
        age_days = (datetime.now() - last_modified).days
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
            suggestions=suggestions
        )

    def _calculate_freshness_score(self, age_days: int) -> int:
        """Calculate freshness score based on file age."""
        max_age = self.config['audit']['thresholds']['max_age_days']
        if age_days <= 30:
            return 100
        elif age_days <= max_age:
            return int(100 * (1 - (age_days - 30) / (max_age - 30)))
        else:
            return max(0, int(50 * (1 - (age_days - max_age) / max_age)))

    def _calculate_completeness_score(self, content: str, word_count: int) -> int:
        """Calculate completeness score based on content analysis."""
        score = 0

        # Word count check
        min_words = self.config['audit']['thresholds']['min_word_count']
        if word_count >= min_words:
            score += 40
        elif word_count >= min_words * 0.5:
            score += 20

        # Required sections check
        required_sections = self.config['content']['required_sections']
        found_sections = 0
        for section in required_sections:
            if re.search(rf'^#+\s*{re.escape(section)}', content, re.MULTILINE | re.IGNORECASE):
                found_sections += 1

        section_score = (found_sections / len(required_sections)) * 60
        score += section_score

        return min(100, int(score))

    def _calculate_structure_score(self, content: str) -> int:
        """Calculate structure score based on markdown formatting."""
        score = 100

        # Check for proper heading hierarchy
        lines = content.split('\n')
        headings = []
        for line in lines:
            if line.startswith('#'):
                level = len(line.split()[0]) if line.split() else 0
                headings.append(level)

        # Check hierarchy (should not skip levels)
        for i in range(1, len(headings)):
            if headings[i] > headings[i-1] + 1:
                score -= 20

        # Check for code blocks (should have language specified)
        code_blocks = re.findall(r'```(\w+)?', content)
        if code_blocks:
            unspecified = code_blocks.count('')
            if unspecified > 0:
                score -= min(30, unspecified * 10)

        # Check for broken links (basic check)
        links = re.findall(r'\[([^\]]+)\]\(([^)]+)\)', content)
        broken_count = 0
        for text, url in links:
            if not url or url.startswith('#') or 'http' in url:
                continue
            # Check if relative link exists
            if not os.path.exists(os.path.join(os.path.dirname(''), url)):
                broken_count += 1

        score -= min(50, broken_count * 15)

        return max(0, score)

    def _calculate_quality_score(self, freshness: int, completeness: int, structure: int) -> int:
        """Calculate overall quality score."""
        return int((freshness * 0.3) + (completeness * 0.4) + (structure * 0.3))

    def _detect_issues(self, content: str, file_path: str,
                      issues: List[Dict], warnings: List[Dict], suggestions: List[Dict]):
        """Detect various issues in the content."""

        # Check for prohibited patterns
        prohibited = self.config['content']['prohibited_patterns']
        for pattern in prohibited:
            matches = re.findall(rf'\b{re.escape(pattern)}\b', content, re.IGNORECASE)
            if matches:
                issues.append({
                    'type': 'prohibited_pattern',
                    'pattern': pattern,
                    'count': len(matches),
                    'message': f'Found {len(matches)} instances of prohibited pattern "{pattern}"'
                })

        # Check for broken internal links
        internal_links = re.findall(r'\[([^\]]+)\]\(([^)]+)\)', content)
        for text, url in internal_links:
            if url.startswith('http') or url.startswith('#'):
                continue
            full_path = os.path.join(os.path.dirname(file_path), url)
            if not os.path.exists(full_path):
                issues.append({
                    'type': 'broken_link',
                    'link_text': text,
                    'url': url,
                    'message': f'Broken internal link: {url}'
                })

        # Check for images without alt text
        images = re.findall(r'!\[([^\]]*)\]\(([^)]+)\)', content)
        for alt_text, url in images:
            if not alt_text.strip():
                warnings.append({
                    'type': 'missing_alt_text',
                    'url': url,
                    'message': f'Image missing alt text: {url}'
                })

        # Check for long paragraphs
        paragraphs = re.split(r'\n\s*\n', content)
        for i, para in enumerate(paragraphs):
            words = len(para.split())
            if words > 150:  # Very long paragraph
                suggestions.append({
                    'type': 'long_paragraph',
                    'paragraph_index': i,
                    'word_count': words,
                    'message': f'Consider breaking up long paragraph ({words} words)'
                })

    def audit_directory(self, directory: str, recursive: bool = True) -> List[AuditResult]:
        """Audit all documentation files in a directory."""
        results = []

        for root, dirs, files in os.walk(directory):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if not self._is_excluded(os.path.join(root, d))]

            for file in files:
                file_path = os.path.join(root, file)
                if self._should_audit_file(file_path):
                    result = self.audit_file(file_path)
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
        for pattern in self.config['audit']['include_patterns']:
            if file_path.endswith(pattern.replace('*', '')):
                return True

        return False

    def _is_excluded(self, path: str) -> bool:
        """Check if path is excluded."""
        for pattern in self.config['audit']['exclude_patterns']:
            if pattern in path or path.startswith(pattern):
                return True
        return False

    def generate_summary(self) -> AuditSummary:
        """Generate summary of audit results."""
        if not self.results:
            return AuditSummary(
                total_files=0, total_words=0, average_age=0, average_quality=0,
                total_issues=0, total_warnings=0, critical_issues=0,
                files_by_quality={}, issues_by_category={},
                oldest_files=[], newest_files=[]
            )

        total_files = len(self.results)
        total_words = sum(r.word_count for r in self.results)
        average_age = sum(r.age_days for r in self.results) / total_files
        average_quality = sum(r.quality_score for r in self.results) / total_files

        total_issues = sum(len(r.issues) for r in self.results)
        total_warnings = sum(len(r.warnings) for r in self.results)
        critical_issues = sum(1 for r in self.results if r.quality_score < 50)

        # Quality distribution
        quality_ranges = {'excellent': 0, 'good': 0, 'fair': 0, 'poor': 0}
        for result in self.results:
            if result.quality_score >= 90:
                quality_ranges['excellent'] += 1
            elif result.quality_score >= 70:
                quality_ranges['good'] += 1
            elif result.quality_score >= 50:
                quality_ranges['fair'] += 1
            else:
                quality_ranges['poor'] += 1

        # Issues by category
        issues_by_category = {}
        for result in self.results:
            for issue in result.issues:
                category = issue.get('type', 'unknown')
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
            newest_files=newest_files
        )

        return self.summary

    def save_results(self, output_file: str, format: str = 'json'):
        """Save audit results to file."""
        if format == 'json':
            data = {
                'timestamp': datetime.now().isoformat(),
                'summary': asdict(self.summary) if self.summary else None,
                'results': [asdict(r) for r in self.results]
            }
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        elif format == 'yaml':
            data = {
                'timestamp': datetime.now().isoformat(),
                'summary': asdict(self.summary) if self.summary else None,
                'results': [asdict(r) for r in self.results]
            }
            with open(output_file, 'w') as f:
                yaml.dump(data, f, default_flow_style=False)

def main():
    parser = argparse.ArgumentParser(description='Documentation Content Quality Audit System')
    parser.add_argument('directory', help='Directory to audit')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--format', choices=['json', 'yaml'], default='json',
                       help='Output format')
    parser.add_argument('--comprehensive', action='store_true',
                       help='Run comprehensive audit')
    parser.add_argument('--quick', action='store_true',
                       help='Run quick audit')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    auditor = DocumentationAuditor(args.config)

    if args.verbose:
        print(f"🔍 Starting documentation audit of: {args.directory}")

    results = auditor.audit_directory(args.directory, recursive=True)

    if args.verbose:
        print(f"📊 Audited {len(results)} files")

    summary = auditor.generate_summary()

    if args.output:
        auditor.save_results(args.output, args.format)
        print(f"💾 Results saved to: {args.output}")

    # Print summary
    print("\n" + "="*60)
    print("📊 DOCUMENTATION AUDIT SUMMARY")
    print("="*60)
    print(f"📁 Total Files: {summary.total_files}")
    print(f"📝 Total Words: {summary.total_words:,}")
    print(f"📅 Average Age: {summary.average_age:.1f} days")
    print(f"⭐ Average Quality: {summary.average_quality:.1f}/100")
    print(f"🚨 Total Issues: {summary.total_issues}")
    print(f"⚠️  Total Warnings: {summary.total_warnings}")
    print(f"🔴 Critical Issues: {summary.critical_issues}")

    print("\n📈 Quality Distribution:")
    for quality, count in summary.files_by_quality.items():
        print(f"  {quality.capitalize()}: {count}")

    print("\n🚨 Top Issues by Category:")
    for category, count in sorted(summary.issues_by_category.items(),
                                key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {category}: {count}")

    if summary.oldest_files:
        print("\n⏰ Oldest Files:")
        for path, age in summary.oldest_files[:3]:
            print(f"  {age} days: {os.path.basename(path)}")

    # Health score
    health_score = min(100, max(0, int(summary.average_quality - (summary.total_issues * 2))))
    health_status = "🟢 Excellent" if health_score >= 90 else \
                   "🟡 Good" if health_score >= 70 else \
                   "🟠 Fair" if health_score >= 50 else "🔴 Poor"

    print(f"\n💚 Documentation Health Score: {health_score}/100 - {health_status}")

if __name__ == '__main__':
    main()
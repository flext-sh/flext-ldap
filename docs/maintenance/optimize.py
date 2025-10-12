#!/usr/bin/env python3
"""Documentation Content Optimization and Enhancement System.

Automatically optimizes and enhances documentation content for better quality,
readability, and maintainability.
"""

import argparse
import json
import operator
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml
from flext_core import FlextCore

# Add parent directory to path for imports
sys.path.insert(0, Path(Path(Path(__file__).resolve()).parent).parent)


@dataclass
class OptimizationResult:
    """Result of optimizing a single file."""

    file_path: str
    changes_made: int
    optimizations: list[dict[str, Any]]
    backup_created: bool
    issues_found: list[dict[str, Any]]


@dataclass
class OptimizationSummary:
    """Summary of optimization results."""

    total_files: int
    total_changes: int
    optimizations_by_type: dict[str, int]
    files_modified: int
    errors_encountered: int
    backup_files_created: FlextCore.Types.StringList


class ContentOptimizer:
    """Main content optimization class."""

    def __init__(self, config_path: str | None = None) -> None:
        self.config = self._load_config(config_path)
        self.backup_dir = os.path.join(Path(__file__).parent, "backups")
        Path(self.backup_dir).mkdir(exist_ok=True, parents=True)

    def _load_config(self, config_path: str | None = None) -> dict[str, Any]:
        """Load configuration."""
        default_config = {
            "optimization": {
                "auto_fix": True,
                "create_backups": True,
                "max_line_length": 120,
                "add_toc_to_long_docs": True,
                "toc_min_headings": 5,
                "fix_common_typos": True,
                "enhance_code_blocks": True,
                "improve_formatting": True,
            },
            "content": {
                "common_typos": {
                    "teh": "the",
                    "recieve": "receive",
                    "seperate": "separate",
                    "occurence": "occurrence",
                    "defininig": "defining",
                    "configuraiton": "configuration",
                    "documenation": "documentation",
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

    def optimize_file(
        self, file_path: str, dry_run: bool = False
    ) -> OptimizationResult:
        """Optimize a single documentation file."""
        try:
            with Path(file_path).open(encoding="utf-8") as f:
                original_content = f.read()
        except Exception as e:
            return OptimizationResult(
                file_path=file_path,
                changes_made=0,
                optimizations=[],
                backup_created=False,
                issues_found=[
                    {"type": "read_error", "message": f"Failed to read file: {e}"}
                ],
            )

        content = original_content
        optimizations = []
        issues = []

        # Apply various optimizations
        content, file_optimizations = self._optimize_content(content, file_path)
        optimizations.extend(file_optimizations)

        # Generate table of contents if needed
        if self.config["optimization"]["add_toc_to_long_docs"]:
            toc_result = self._add_table_of_contents(content, file_path)
            if toc_result["added"]:
                content = toc_result["content"]
                optimizations.append({
                    "type": "toc_added",
                    "description": "Added table of contents to long document",
                })

        # Check for issues
        issues.extend(self._check_for_issues(content, file_path))

        changes_made = len(optimizations)

        # Create backup if changes were made
        backup_created = False
        if (
            changes_made > 0
            and self.config["optimization"]["create_backups"]
            and not dry_run
        ):
            backup_path = self._create_backup(file_path, original_content)
            backup_created = backup_path is not None

        # Write optimized content
        if not dry_run and content != original_content:
            try:
                with Path(file_path).open("w", encoding="utf-8") as f:
                    f.write(content)
            except Exception as e:
                issues.append({
                    "type": "write_error",
                    "message": f"Failed to write optimized content: {e}",
                })

        return OptimizationResult(
            file_path=file_path,
            changes_made=changes_made,
            optimizations=optimizations,
            backup_created=backup_created,
            issues_found=issues,
        )

    def _optimize_content(
        self, content: str, file_path: str
    ) -> tuple[str, list[dict[str, Any]]]:
        """Apply content optimizations."""
        optimizations = []

        # Fix trailing whitespace
        if self.config["optimization"]["improve_formatting"]:
            content.count("\n")
            lines = content.split("\n")
            cleaned_lines = [line.rstrip() for line in lines]
            new_content = "\n".join(cleaned_lines)

            if new_content != content:
                content = new_content
                optimizations.append({
                    "type": "trailing_whitespace",
                    "description": "Removed trailing whitespace from lines",
                })

        # Fix common typos
        if self.config["optimization"]["fix_common_typos"]:
            for typo, correction in self.config["content"]["common_typos"].items():
                pattern = rf"\b{re.escape(typo)}\b"
                if re.search(pattern, content, re.IGNORECASE):
                    content = re.sub(pattern, correction, content, flags=re.IGNORECASE)
                    optimizations.append({
                        "type": "typo_fix",
                        "typo": typo,
                        "correction": correction,
                        "description": f"Fixed typo: {typo} → {correction}",
                    })

        # Enhance code blocks
        if self.config["optimization"]["enhance_code_blocks"]:
            content, code_optimizations = self._enhance_code_blocks(content)
            optimizations.extend(code_optimizations)

        # Fix line length issues
        if self.config["optimization"]["max_line_length"]:
            content, length_optimizations = self._fix_line_lengths(content)
            optimizations.extend(length_optimizations)

        return content, optimizations

    def _enhance_code_blocks(self, content: str) -> tuple[str, list[dict[str, Any]]]:
        """Enhance code blocks with better formatting."""
        optimizations = []

        # Find code blocks without language specification
        lines = content.split("\n")
        in_code_block = False

        for i, line in enumerate(lines):
            if line.strip().startswith("```"):
                if not in_code_block:
                    # Start of code block
                    in_code_block = True
                    # Check if language is specified
                    code_marker = line.strip()
                    if code_marker == "```" or len(code_marker) == 3:
                        # Try to detect language from content
                        detected_lang = self._detect_code_language(lines, i)
                        if detected_lang:
                            lines[i] = f"``` {detected_lang}"
                            optimizations.append({
                                "type": "code_block_language",
                                "description": f"Added language specification: {detected_lang}",
                                "line": i + 1,
                            })
                else:
                    # End of code block
                    in_code_block = False

        return "\n".join(lines), optimizations

    def _detect_code_language(
        self, lines: FlextCore.Types.StringList, start_index: int
    ) -> str | None:
        """Detect programming language from code block content."""
        # Look at the next few lines for language clues
        for i in range(start_index + 1, min(start_index + 10, len(lines))):
            line = lines[i].strip()
            if line.startswith("```"):
                break

            # Python indicators
            if re.search(r"\bdef\b|\bimport\b|\bfrom\b.*import|\bclass\b", line):
                return "python"

            # Bash/shell indicators
            if re.search(r"\$\{|\becho\b|\bgrep\b|\bsed\b|\bawk\b", line):
                return "bash"

            # JSON indicators
            if re.search(r'^\s*{\s*"|^"', line):
                return "json"

            # YAML indicators
            if re.search(r"^\s*\w+:\s|^---", line):
                return "yaml"

            # JavaScript indicators
            if re.search(r"\bfunction\b|\bconst\b|\blet\b|\bvar\b", line):
                return "javascript"

        return None

    def _fix_line_lengths(self, content: str) -> tuple[str, list[dict[str, Any]]]:
        """Fix overly long lines by breaking them appropriately."""
        optimizations = []
        max_length = self.config["optimization"]["max_line_length"]

        lines = content.split("\n")
        for i, line in enumerate(lines):
            if len(line) > max_length and not line.strip().startswith("```"):
                # Try to break at natural points
                if "," in line and len(line) > max_length + 20:
                    # Break after comma
                    parts = line.split(",")
                    if len(parts) > 1:
                        new_lines = []
                        current_line = parts[0]
                        for part in parts[1:]:
                            if len(current_line + "," + part) > max_length:
                                new_lines.append(current_line + ",")
                                current_line = "    " + part  # Indent continuation
                            else:
                                current_line += "," + part
                        new_lines.append(current_line)

                        lines[i] = "\n".join(new_lines)
                        optimizations.append({
                            "type": "line_length",
                            "description": f"Fixed long line by breaking at commas (line {i + 1})",
                        })

        return "\n".join(lines), optimizations

    def _add_table_of_contents(self, content: str, file_path: str) -> dict[str, Any]:
        """Add table of contents to long documents."""
        lines = content.split("\n")

        # Count headings
        headings = []
        for i, line in enumerate(lines):
            match = re.match(r"^(#{1,6})\s+(.+)$", line)
            if match:
                level = len(match.group(1))
                title = match.group(2)
                headings.append((i, level, title))

        # Only add TOC if enough headings and not already present
        min_headings = self.config["optimization"]["toc_min_headings"]
        if len(headings) >= min_headings and not self._has_table_of_contents(content):
            # Generate TOC
            toc_lines = ["## Table of Contents", ""]
            for _line_num, level, title in headings:
                indent = "  " * (level - 1)
                # Create anchor link
                anchor = re.sub(r"[^\w\s-]", "", title).replace(" ", "-").lower()
                toc_lines.append(f"{indent}- [{title}](#{anchor})")

            toc_lines.append("")
            toc_content = "\n".join(toc_lines)

            # Insert after the first heading
            first_heading_idx = headings[0][0]
            lines.insert(first_heading_idx + 1, toc_content)

            return {"added": True, "content": "\n".join(lines)}

        return {"added": False, "content": content}

    def _has_table_of_contents(self, content: str) -> bool:
        """Check if document already has a table of contents."""
        return (
            re.search(
                r"## Table of Contents|## Contents|## TOC", content, re.IGNORECASE
            )
            is not None
        )

    def _check_for_issues(self, content: str, file_path: str) -> list[dict[str, Any]]:
        """Check for potential issues in the content."""
        issues = []

        # Check for broken internal links
        internal_links = re.findall(r"\[([^\]]+)\]\(([^)]+)\)", content)
        for text, url in internal_links:
            if not url.startswith(("http", "https", "#")):
                # Check if relative file exists
                file_dir = Path(file_path).parent
                full_path = os.path.join(file_dir, url)
                if not Path(full_path).exists():
                    issues.append({
                        "type": "broken_link",
                        "text": text,
                        "url": url,
                        "message": f"Broken internal link: {url}",
                    })

        # Check for very long paragraphs
        paragraphs = re.split(r"\n\s*\n", content)
        for i, para in enumerate(paragraphs):
            word_count = len(para.split())
            if word_count > 200:  # Very long paragraph
                issues.append({
                    "type": "long_paragraph",
                    "paragraph": i,
                    "word_count": word_count,
                    "message": f"Very long paragraph ({word_count} words) - consider breaking up",
                })

        return issues

    def _create_backup(self, file_path: str, content: str) -> str | None:
        """Create a backup of the original file."""
        try:
            filename = Path(file_path).name
            timestamp = __import__("time").strftime("%Y%m%d_%H%M%S")
            backup_name = f"{filename}.{timestamp}.backup"
            backup_path = os.path.join(self.backup_dir, backup_name)

            with Path(backup_path).open("w", encoding="utf-8") as f:
                f.write(content)

            return backup_path
        except Exception:
            return None

    def optimize_directory(
        self, directory: str, dry_run: bool = False
    ) -> list[OptimizationResult]:
        """Optimize all files in a directory."""
        results = []

        for root, dirs, files in os.walk(directory):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if not self._is_excluded(os.path.join(root, d))]

            for file in files:
                if file.endswith((".md", ".mdx")):
                    file_path = os.path.join(root, file)
                    if not self._is_excluded(file_path):
                        result = self.optimize_file(file_path, dry_run)
                        results.append(result)

        return results

    def _is_excluded(self, path: str) -> bool:
        """Check if path is excluded."""
        # Basic exclusion - could be made configurable
        return ".git" in path or "node_modules" in path or "backups" in path

    def generate_summary(
        self, results: list[OptimizationResult]
    ) -> OptimizationSummary:
        """Generate summary of optimization results."""
        total_files = len(results)
        total_changes = sum(r.changes_made for r in results)

        optimizations_by_type = {}
        files_modified = sum(1 for r in results if r.changes_made > 0)
        errors_encountered = sum(1 for r in results if r.issues_found)
        backup_files_created = []

        for result in results:
            for opt in result.optimizations:
                opt_type = opt["type"]
                optimizations_by_type[opt_type] = (
                    optimizations_by_type.get(opt_type, 0) + 1
                )

            if result.backup_created:
                backup_files_created.append(result.file_path)

        return OptimizationSummary(
            total_files=total_files,
            total_changes=total_changes,
            optimizations_by_type=optimizations_by_type,
            files_modified=files_modified,
            errors_encountered=errors_encountered,
            backup_files_created=backup_files_created,
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Documentation Content Optimization and Enhancement System"
    )
    parser.add_argument("directory", help="Directory to optimize")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--output", "-o", help="Output file for results")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be changed without making changes",
    )
    parser.add_argument(
        "--enhance-all", action="store_true", help="Apply all available optimizations"
    )
    parser.add_argument(
        "--fix-typos", action="store_true", help="Only fix common typos"
    )
    parser.add_argument(
        "--add-toc",
        action="store_true",
        help="Only add table of contents to long documents",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    optimizer = ContentOptimizer(args.config)

    if args.verbose:
        pass

    results = optimizer.optimize_directory(args.directory, args.dry_run)
    summary = optimizer.generate_summary(results)

    if args.output:
        output_data = {
            "timestamp": __import__("time").time(),
            "summary": asdict(summary),
            "results": [asdict(r) for r in results],
        }
        with Path(args.output).open("w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2, default=str)

    # Print summary

    if summary.optimizations_by_type:
        for _opt_type, _count in sorted(
            summary.optimizations_by_type.items(),
            key=operator.itemgetter(1),
            reverse=True,
        ):
            pass

    if summary.backup_files_created and args.verbose:
        for _file_path in summary.backup_files_created[:5]:
            pass

    (
        summary.files_modified / summary.total_files * 100
    ) if summary.total_files > 0 else 0
    if args.dry_run:
        pass

    # Show files with most changes
    if args.verbose and results:
        files_by_changes = sorted(
            [(r.file_path, r.changes_made) for r in results if r.changes_made > 0],
            key=operator.itemgetter(1),
            reverse=True,
        )

        if files_by_changes:
            for _file_path, _changes in files_by_changes[:5]:
                pass


if __name__ == "__main__":
    main()

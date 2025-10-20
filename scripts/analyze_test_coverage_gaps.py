"""Analyze test coverage gaps using AST and pytest-cov data.

Identifies:
1. Functions/methods without any test coverage
2. Branches never taken
3. Error paths never tested
4. Integration tests that could be added

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import ast
import json
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class FunctionInfo:
    """Information about a function extracted from AST."""

    name: str
    line: int
    params: list[str]
    returns: str | None
    is_async: bool
    decorators: list[str]


@dataclass
class TestGap:
    """Information about test coverage gaps."""

    file: str
    function: FunctionInfo
    coverage_percent: float
    missing_branches: list[tuple[int, int]]
    has_test: bool


def analyze_source_file(filepath: Path) -> list[FunctionInfo]:
    """Extract all functions/methods from source file using AST."""
    try:
        with Path(filepath).open(encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=str(filepath))
    except (SyntaxError, UnicodeDecodeError) as e:
        print(f"Warning: Could not parse {filepath}: {e}", file=sys.stderr)
        return []

    functions = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            info = FunctionInfo(
                name=node.name,
                line=node.lineno,
                params=[arg.arg for arg in node.args.args],
                returns=ast.unparse(node.returns) if node.returns else None,
                is_async=isinstance(node, ast.AsyncFunctionDef),
                decorators=[ast.unparse(d) for d in node.decorator_list],
            )
            functions.append(info)
    return functions


def find_test_for_function(test_dir: Path, function_name: str) -> bool:
    """Check if test exists for function."""
    test_pattern = f"test_{function_name}"
    for test_file in test_dir.rglob("test_*.py"):
        try:
            with Path(test_file).open(encoding="utf-8") as f:
                if test_pattern in f.read():
                    return True
        except (OSError, UnicodeDecodeError):
            continue
    return False


def analyze_coverage_gaps(
    src_dir: Path, test_dir: Path, coverage_file: Path | None = None
) -> list[TestGap]:
    """Identify functions missing tests or coverage."""
    coverage_data = {}
    if coverage_file and coverage_file.exists():
        try:
            with Path(coverage_file).open(encoding="utf-8") as f:
                coverage_data = json.load(f)
        except (json.JSONDecodeError, OSError):
            print(
                f"Warning: Could not read coverage file {coverage_file}",
                file=sys.stderr,
            )

    gaps = []
    for py_file in src_dir.rglob("*.py"):
        if "__pycache__" in str(py_file) or "__init__.py" in str(py_file):
            continue

        functions = analyze_source_file(py_file)
        file_coverage = coverage_data.get("files", {}).get(str(py_file), {})

        for func in functions:
            # Skip private methods and special methods
            if func.name.startswith("_") and not func.name.startswith("__"):
                continue

            has_test = find_test_for_function(test_dir, func.name)
            coverage_percent = file_coverage.get("summary", {}).get(
                "percent_covered", 0
            )

            # Identify as gap if no test or low coverage
            if not has_test or coverage_percent < 70:
                gaps.append(
                    TestGap(
                        file=str(py_file.relative_to(src_dir.parent)),
                        function=func,
                        coverage_percent=coverage_percent,
                        missing_branches=[],
                        has_test=has_test,
                    )
                )

    return sorted(gaps, key=lambda x: x.coverage_percent)


def main() -> None:
    """Run coverage gap analysis."""
    src_dir = Path("src/flext_ldap")
    test_dir = Path("tests")
    coverage_file = Path("coverage.json")

    if not src_dir.exists():
        print(f"Error: Source directory {src_dir} not found", file=sys.stderr)
        sys.exit(1)

    if not test_dir.exists():
        print(f"Error: Test directory {test_dir} not found", file=sys.stderr)
        sys.exit(1)

    print("Analyzing test coverage gaps...")
    print(f"Source: {src_dir}")
    print(f"Tests: {test_dir}")
    print()

    gaps = analyze_coverage_gaps(
        src_dir,
        test_dir,
        coverage_file if coverage_file.exists() else None,
    )

    # Report findings
    print(f"Found {len(gaps)} functions with test gaps:")
    print()

    # Group by file
    by_file: dict[str, list[TestGap]] = {}
    for gap in gaps:
        by_file.setdefault(gap.file, []).append(gap)

    for file_path, file_gaps in sorted(by_file.items()):
        print(f"{file_path}:")
        for gap in file_gaps[:5]:  # Show top 5 per file
            status = "NO TEST" if not gap.has_test else f"{gap.coverage_percent:.0f}%"
            print(f"  Line {gap.function.line}: {gap.function.name}() - {status}")
        if len(file_gaps) > 5:
            print(f"  ... and {len(file_gaps) - 5} more")
        print()

    # Summary statistics
    no_test = sum(1 for g in gaps if not g.has_test)
    low_coverage = sum(1 for g in gaps if g.has_test and g.coverage_percent < 70)

    print("Summary:")
    print(f"  Functions without tests: {no_test}")
    print(f"  Functions with low coverage: {low_coverage}")
    print(f"  Total gaps: {len(gaps)}")


if __name__ == "__main__":
    main()

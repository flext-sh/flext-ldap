#!/usr/bin/env python3
"""Check for broad exception handlers in Python files.

This script identifies uses of 'except Exception:' and 'except BaseException:'
which are considered too broad for production code. Specific exception types
should be used instead.

Usage:
    python scripts/check_broad_exceptions.py src/
    python scripts/check_broad_exceptions.py src/flext_ldap/api.py

Exit codes:
    0 - No violations found
    1 - Violations found

Integration:
    - Add to Makefile: make check-exceptions
    - Add to CI/CD pipeline
    - Add to pre-commit hooks
"""

import re
import sys
from pathlib import Path
from typing import NamedTuple

# Pattern to match broad exception handlers
BROAD_PATTERN = re.compile(
    r"^\s*except\s+(Exception|BaseException)\s*(as\s+\w+)?\s*:", re.MULTILINE
)

# Files allowed to have broad exception handlers (with justification)
ALLOWED_FILES = {
    # File I/O operations - use broad Exception after specific OSError/JSONDecodeError
    "failure_tracker.py": [79, 114, 148],  # Fallback after OSError, JSONDecodeError
}


class Violation(NamedTuple):
    """Represents a broad exception handler violation."""

    filepath: Path
    line_number: int
    line_content: str
    is_allowed: bool


def check_file(filepath: Path) -> list[Violation]:
    """Check a single file for broad exception handlers.

    Args:
        filepath: Path to Python file to check

    Returns:
        List of violations found

    """
    violations = []

    try:
        content = filepath.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        print(f"Warning: Could not read {filepath}: {e}", file=sys.stderr)
        return violations

    # Find all matches
    for match in BROAD_PATTERN.finditer(content):
        line_number = content[: match.start()].count("\n") + 1
        line_start = content.rfind("\n", 0, match.start()) + 1
        line_end = content.find("\n", match.end())
        if line_end == -1:
            line_end = len(content)
        line_content = content[line_start:line_end].strip()

        # Check if this line is allowed
        is_allowed = False
        if filepath.name in ALLOWED_FILES:
            allowed_lines = ALLOWED_FILES[filepath.name]
            is_allowed = line_number in allowed_lines

        violations.append(
            Violation(
                filepath=filepath,
                line_number=line_number,
                line_content=line_content,
                is_allowed=is_allowed,
            )
        )

    return violations


def check_paths(paths: list[str]) -> tuple[list[Violation], list[Violation]]:
    """Check all Python files in given paths.

    Args:
        paths: List of file or directory paths to check

    Returns:
        Tuple of (real_violations, allowed_violations)

    """
    real_violations = []
    allowed_violations = []

    for path_str in paths:
        path = Path(path_str)

        if not path.exists():
            print(f"Warning: Path does not exist: {path}", file=sys.stderr)
            continue

        # Get all Python files
        py_files = path.rglob("*.py") if path.is_dir() else [path]

        # Check each file
        for py_file in py_files:
            violations = check_file(py_file)
            for violation in violations:
                if violation.is_allowed:
                    allowed_violations.append(violation)
                else:
                    real_violations.append(violation)

    return real_violations, allowed_violations


def format_violation_report(
    violations: list[Violation], allowed: list[Violation]
) -> str:
    """Format violations into a readable report.

    Args:
        violations: List of real violations
        allowed: List of allowed violations

    Returns:
        Formatted report string

    """
    lines = []

    if violations:
        lines.extend([
            "\n❌ BROAD EXCEPTION HANDLERS FOUND\n",
            "The following files use broad 'except Exception:' handlers.",
            "Please use specific exception types instead.\n",
        ])

        # Group by file
        by_file: dict[Path, list[Violation]] = {}
        for v in violations:
            by_file.setdefault(v.filepath, []).append(v)

        for filepath in sorted(by_file.keys()):
            file_violations = by_file[filepath]
            lines.append(f"\n{filepath}:")
            lines.extend(
                f"  Line {v.line_number}: {v.line_content}" for v in file_violations
            )

        lines.extend([
            "\n" + "=" * 70,
            f"Total violations: {len(violations)}",
            "=" * 70,
            "\nSee EXCEPTION_QUICK_REFERENCE.md for replacement patterns.",
        ])

    if allowed:
        lines.extend([
            "\n✓ ALLOWED EXCEPTIONS (with justification)\n",
            *[f"{v.filepath.name}:{v.line_number} - {v.line_content}" for v in allowed],
            f"\nTotal allowed: {len(allowed)}",
        ])

    if not violations and not allowed:
        lines.append("\n✅ SUCCESS: No broad exception handlers found!")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Main entry point.

    Args:
        argv: Command line arguments (defaults to sys.argv[1:])

    Returns:
        Exit code (0 for success, 1 for violations found)

    """
    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        print("Usage: python check_broad_exceptions.py <path> [<path> ...]")
        print("\nExamples:")
        print("  python check_broad_exceptions.py src/")
        print("  python check_broad_exceptions.py src/flext_ldap/api.py")
        print("  python check_broad_exceptions.py src/ tests/")
        return 1

    # Check all paths
    violations, allowed = check_paths(argv)

    # Print report
    report = format_violation_report(violations, allowed)
    print(report)

    # Return exit code
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Improved script to fix all G004 logging f-string violations."""

import re
from pathlib import Path


def fix_g004_in_file(file_path: Path) -> int:
    """Fix G004 violations in a single file."""
    if not file_path.exists():
        return 0

    content = file_path.read_text(encoding="utf-8")
    original_content = content
    fixes = 0

    # Pattern for f-strings in logging calls
    # This handles: logger.info(f"text {var}")
    def fix_fstring_logging(match: re.Match[str]) -> str:
        log_level = match.group(1)
        fstring_content = match.group(2)

        # Extract variables from {var} patterns
        variables = re.findall(r"\{([^}]+)\}", fstring_content)

        if not variables:
            # No variables, just remove the f prefix
            return f'logger.{log_level}("{fstring_content}")'

        # Replace {var} with %s
        format_string = re.sub(r"\{[^}]+\}", "%s", fstring_content)

        # Build the new logging call
        var_list = ", ".join(variables)
        return f'logger.{log_level}("{format_string}", {var_list})'

    # Fix f-strings in logging calls
    content = re.sub(
        r'logger\.(debug|info|warning|error|exception|critical)\(f"([^"]*)"(?:\)|,)',
        lambda m: fix_fstring_logging(m) + (")" if m.group(0).endswith(")") else ", "),
        content,
    )

    # Fix single quote f-strings
    content = re.sub(
        r"logger\.(debug|info|warning|error|exception|critical)\(f'([^']*)'(?:\)|,)",
        lambda m: f'logger.{m.group(1)}("{m.group(2)}")'
        + (")" if m.group(0).endswith(")") else ", "),
        content,
    )

    # Fix syntax errors introduced by previous script
    # Remove double closing parentheses
    content = re.sub(r"\)\)", ")", content)

    # Fix malformed logging calls like: logger.info("text"), extra_param)
    content = re.sub(r"(logger\.\w+\([^)]+)\), ([^)]+\))", r"\1, \2", content)

    if content != original_content:
        file_path.write_text(content, encoding="utf-8")
        fixes = (
            original_content.count('f"')
            + original_content.count("f'")
            - (content.count('f"') + content.count("f'"))
        )

    return max(0, fixes)


def main() -> None:
    """Fix all G004 violations in the codebase."""
    src_dir = Path("/home/marlonsc/pyauto/ldap-core-shared/src")
    tests_dir = Path("/home/marlonsc/pyauto/ldap-core-shared/tests")
    total_fixes = 0

    for directory in [src_dir, tests_dir]:
        if directory.exists():
            for py_file in directory.rglob("*.py"):
                fixes = fix_g004_in_file(py_file)
                if fixes > 0:
                    total_fixes += fixes


if __name__ == "__main__":
    main()

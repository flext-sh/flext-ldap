#!/usr/bin/env python3
"""Script to fix all G004 logging f-string violations."""

import re
from pathlib import Path


def fix_g004_in_file(file_path: Path) -> int:
    """Fix G004 violations in a single file."""
    if not file_path.exists():
        return 0

    content = file_path.read_text(encoding="utf-8")
    original_content = content
    fixes = 0

    # Pattern to match f-string logging statements
    patterns = [
        # logger.info(f"...")
        (
            r'logger\.(debug|info|warning|error|exception|critical)\(f"([^"]*)"',
            lambda m: f'logger.{m.group(1)}("{m.group(2)}")',
        ),
        # logger.info(f'...')
        (
            r"logger\.(debug|info|warning|error|exception|critical)\(f'([^']*)'",
            lambda m: f'logger.{m.group(1)}("{m.group(2)}")',
        ),
        # Handle simple f-string with single variable: f"text {var}"
        (
            r'logger\.(debug|info|warning|error|exception|critical)\(f"([^"]*\{[^}]+\}[^"]*)"',
            lambda m: convert_fstring_to_format(m.group(1), m.group(2)),
        ),
        # Handle complex f-strings with multiple variables
        (
            r'logger\.(debug|info|warning|error|exception|critical)\(\s*f"([^"]*)"',
            lambda m: convert_complex_fstring(m.group(1), m.group(2)),
        ),
    ]

    for pattern, replacement in patterns:
        if callable(replacement):

            def repl_func(match: re.Match[str]) -> str:
                try:
                    return replacement(match)
                except:
                    return match.group(0)  # Return original if conversion fails

            content = re.sub(pattern, repl_func, content)
        else:
            content = re.sub(pattern, replacement, content)

    if content != original_content:
        file_path.write_text(content, encoding="utf-8")
        fixes = (
            original_content.count('f"')
            + original_content.count("f'")
            - (content.count('f"') + content.count("f'"))
        )

    return max(0, fixes)


def convert_fstring_to_format(log_level: str, fstring_content: str) -> str:
    """Convert simple f-string to % formatting."""
    # Extract variables from {var} patterns
    variables = re.findall(r"\{([^}]+)\}", fstring_content)

    if not variables:
        return f'logger.{log_level}("{fstring_content}")'

    # Replace {var} with %s
    format_string = re.sub(r"\{[^}]+\}", "%s", fstring_content)

    # Build the new logging call
    if len(variables) == 1:
        return f'logger.{log_level}("{format_string}", {variables[0]})'
    var_list = ", ".join(variables)
    return f'logger.{log_level}("{format_string}", {var_list})'


def convert_complex_fstring(log_level: str, fstring_content: str) -> str:
    """Convert complex f-string to % formatting."""
    # Handle format specifiers like {var:.3f}
    variables = []
    format_string = fstring_content

    # Find all {var} and {var:format} patterns
    for match in re.finditer(r"\{([^}:]+)(?::([^}]+))?\}", fstring_content):
        var_name = match.group(1)
        format_spec = match.group(2)

        variables.append(var_name)

        if format_spec:
            if "f" in format_spec or "d" in format_spec or "s" in format_spec:
                # Keep the format specifier
                format_replacement = f"%{format_spec}"
            else:
                format_replacement = "%s"
        else:
            format_replacement = "%s"

        format_string = format_string.replace(match.group(0), format_replacement, 1)

    if variables:
        var_list = ", ".join(variables)
        return f'logger.{log_level}("{format_string}", {var_list})'
    return f'logger.{log_level}("{format_string}")'


def main() -> None:
    """Fix all G004 violations in the codebase."""
    src_dir = Path("/home/marlonsc/pyauto/ldap-core-shared/src")
    total_fixes = 0

    for py_file in src_dir.rglob("*.py"):
        fixes = fix_g004_in_file(py_file)
        if fixes > 0:
            total_fixes += fixes


if __name__ == "__main__":
    main()

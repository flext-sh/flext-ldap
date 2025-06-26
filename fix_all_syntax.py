#!/usr/bin/env python3
"""Comprehensive syntax error fixing script for 100% PEP compliance."""

import ast
import re
from pathlib import Path


def fix_file_syntax(file_path: Path) -> tuple[bool, str]:
    """Fix syntax errors in a single file."""
    try:
        content = file_path.read_text(encoding="utf-8")
        original_content = content

        # Apply systematic fixes
        content = apply_syntax_fixes(content)

        # Test if the file compiles
        try:
            ast.parse(content)
            if content != original_content:
                file_path.write_text(content, encoding="utf-8")
                return True, "Fixed"
            return False, "No changes needed"
        except SyntaxError as e:
            return False, f"Syntax error remains: {e}"

    except Exception as e:
        return False, f"Error processing file: {e}"


def apply_syntax_fixes(content: str) -> str:
    """Apply comprehensive syntax fixes."""
    # Fix missing closing parentheses in common patterns
    fixes = [
        # Fix uuid.uuid4() calls
        (r"uuid\.uuid4\(\s*(?=\n)", "uuid.uuid4()"),
        (r"str\(uuid\.uuid4\(\s*(?=\n)", "str(uuid.uuid4())"),

        # Fix datetime calls
        (r"datetime\.now\(UTC\s*(?=\n)", "datetime.now(UTC)"),
        (r"datetime\.now\(\s*(?=\n)", "datetime.now()"),

        # Fix time calls
        (r"time\.time\(\s*(?=\n)", "time.time()"),

        # Fix isinstance calls missing closing parenthesis
        (r"isinstance\([^)]+(?=:)", lambda m: m.group(0) + ")"),

        # Fix raise statements missing closing parenthesis
        (r"raise\s+\w+Error\([^)]+(?=\n)", lambda m: m.group(0) + ")"),

        # Fix function calls at end of line missing )
        (r"([a-zA-Z_]\w*\([^)]*[^)])\s*(?=\n)", r"\1)"),

        # Fix double closing parentheses
        (r"\)\)", ")"),

        # Fix missing commas in function calls
        (r"(\w+\([^)]+)\s+(\w+=[^,)]+)", r"\1, \2"),

        # Fix missing closing brackets/parentheses in list comprehensions
        (r"\[([^]]+)(?=\n)", r"[\1]"),

        # Fix incomplete f-strings and logging
        (r'logger\.\w+\(f?"[^"]*"[^)]*(?=\n)', lambda m: m.group(0) + ")"),

        # Fix incomplete method definitions
        (r"def\s+\w+\([^)]*(?=:)", lambda m: m.group(0) + ")"),

        # Fix incomplete class definitions
        (r"class\s+\w+\([^)]*(?=:)", lambda m: m.group(0) + ")"),

        # Fix missing closing in tuple definitions
        (r"\(([^)]+,\s*(?=\n))", r"(\1)"),
    ]

    for pattern, replacement in fixes:
        if callable(replacement):
            content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
        else:
            content = re.sub(pattern, replacement, content, flags=re.MULTILINE)

    return content


def main() -> None:
    """Fix all syntax errors systematically."""
    src_dir = Path("/home/marlonsc/pyauto/ldap-core-shared/src")

    total_files = 0
    fixed_files = 0

    for py_file in src_dir.rglob("*.py"):
        total_files += 1
        success, message = fix_file_syntax(py_file)

        if success:
            fixed_files += 1
        elif "Syntax error remains" in message:
            pass
        # Skip files with no changes


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Fix common syntax errors introduced by the G004 script."""

import re
from pathlib import Path


def fix_syntax_errors_in_file(file_path: Path) -> int:
    """Fix common syntax errors in a file."""
    if not file_path.exists():
        return 0

    try:
        content = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return 0

    original_content = content
    fixes = 0

    # Fix missing closing parentheses
    patterns = [
        # Fix uuid.uuid4( without closing )
        (r"uuid\.uuid4\(\s*$", "uuid.uuid4()"),
        # Fix str(uuid.uuid4( without closing ))
        (r"str\(uuid\.uuid4\(\s*$", "str(uuid.uuid4())"),
        # Fix function calls missing closing parentheses at end of line
        (r"([a-zA-Z_][a-zA-Z0-9_]*\([^)]+)\s*$", r"\1)"),
        # Fix double closing parentheses
        (r"\)\)", ")"),
        # Fix missing closing ) in isinstance calls
        (r"isinstance\([^)]+\):\s*$", lambda m: m.group(0).replace("):", "):")),
        # Fix missing closing parentheses in raise statements
        (r"raise [A-Z][a-zA-Z]*\([^)]+$", lambda m: m.group(0) + ")"),
    ]

    for pattern, replacement in patterns:
        if callable(replacement):
            content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
        else:
            content = re.sub(pattern, replacement, content, flags=re.MULTILINE)

        if content != original_content:
            fixes += 1
            original_content = content

    # Fix specific common errors
    # Fix missing parentheses in time.time() calls
    content = re.sub(r"time\.time\(\s*$", "time.time()", content, flags=re.MULTILINE)

    # Fix missing parentheses in datetime.now() calls
    content = re.sub(
        r"datetime\.now\([^)]*$",
        lambda m: m.group(0) + ")",
        content,
        flags=re.MULTILINE,
    )

    if content != original_content:
        file_path.write_text(content, encoding="utf-8")
        return fixes

    return 0


def main() -> None:
    """Fix syntax errors in the codebase."""
    src_dir = Path("/home/marlonsc/pyauto/ldap-core-shared/src")
    total_fixes = 0

    for py_file in src_dir.rglob("*.py"):
        try:
            fixes = fix_syntax_errors_in_file(py_file)
            if fixes > 0:
                total_fixes += fixes
        except Exception:
            pass


if __name__ == "__main__":
    main()

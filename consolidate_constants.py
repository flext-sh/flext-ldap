#!/usr/bin/env python3
"""Consolidate duplicated constants across the codebase.

This script follows ZERO TOLERANCE - FIX REAL principle by systematically
removing code duplication and centralizing constants in utils.constants.

Following LDAP Core Shared requirements:
- Remove ALL duplicated magic numbers
- Centralize constants for maintainability
- Preserve functionality while eliminating redundancy
"""

import re
from pathlib import Path


def consolidate_constants() -> None:
    """Consolidate duplicated constants across the codebase."""
    src_dir = Path("src/ldap_core_shared")

    # Patterns to replace with imports from utils.constants
    replacements = [
        # Magic number constants
        (
            r"DEFAULT_MAX_ITEMS = 100",
            "from ldap_core_shared.utils.constants import DEFAULT_MAX_ITEMS",
        ),
        (
            r"DEFAULT_TIMEOUT_SECONDS = 30",
            "from ldap_core_shared.utils.constants import DEFAULT_TIMEOUT_SECONDS",
        ),
        (
            r"DEFAULT_LARGE_LIMIT = 1000",
            "from ldap_core_shared.utils.constants import DEFAULT_LARGE_LIMIT",
        ),
        (
            r"LDAPS_DEFAULT_PORT = 636",
            "from ldap_core_shared.utils.constants import LDAPS_DEFAULT_PORT",
        ),
        (
            r"LDAP_DEFAULT_PORT = 389",
            "from ldap_core_shared.utils.constants import LDAP_DEFAULT_PORT",
        ),
        # Inline magic numbers in code
        (r"\b100\b(?=.*# Convert to|.*percent|.*DEFAULT_MAX)", "DEFAULT_MAX_ITEMS"),
        (r"\b1000\b(?=.*# Convert to|.*limit|.*DEFAULT_LARGE)", "DEFAULT_LARGE_LIMIT"),
        (r"\b30\b(?=.*timeout|.*second)", "DEFAULT_TIMEOUT_SECONDS"),
        (r"\b389\b(?=.*port|.*LDAP)", "LDAP_DEFAULT_PORT"),
        (r"\b636\b(?=.*port|.*LDAPS)", "LDAPS_DEFAULT_PORT"),
    ]

    files_processed = 0
    files_with_changes = 0

    # Process all Python files except constants.py itself
    for py_file in src_dir.rglob("*.py"):
        if py_file.name == "constants.py":
            continue

        try:
            with open(py_file, encoding="utf-8") as f:
                content = f.read()

            original_content = content
            has_constants_import = (
                "from ldap_core_shared.utils.constants import" in content
            )
            imports_to_add = set()

            # Apply replacements
            for pattern, replacement in replacements:
                if re.search(pattern, content):
                    if replacement.startswith("from ldap_core_shared"):
                        # This is an import statement
                        imports_to_add.add(replacement)
                        # Remove the duplicate constant definition
                        content = re.sub(
                            f"^{pattern}.*$", "", content, flags=re.MULTILINE
                        )
                    else:
                        # This is a constant name replacement
                        content = re.sub(pattern, replacement, content)
                        # Ensure import is present
                        const_name = replacement
                        imports_to_add.add(
                            f"from ldap_core_shared.utils.constants import {const_name}"
                        )

            # Add missing imports
            if imports_to_add and not has_constants_import:
                # Find import section
                import_section_end = 0
                lines = content.split("\n")
                for i, line in enumerate(lines):
                    if line.startswith(("from ", "import ")):
                        import_section_end = i + 1
                    elif line.strip() == "":
                        continue
                    else:
                        break

                # Add consolidated import
                all_constants = set()
                for imp in imports_to_add:
                    if "import" in imp:
                        const_name = imp.split("import ")[-1]
                        all_constants.add(const_name)

                if all_constants:
                    new_import = f"from ldap_core_shared.utils.constants import {', '.join(sorted(all_constants))}"
                    lines.insert(import_section_end, new_import)
                    content = "\n".join(lines)

            # Clean up extra newlines
            content = re.sub(r"\n\n\n+", "\n\n", content)

            if content != original_content:
                with open(py_file, "w", encoding="utf-8") as f:
                    f.write(content)
                files_with_changes += 1

            files_processed += 1

        except Exception:
            pass


if __name__ == "__main__":
    consolidate_constants()

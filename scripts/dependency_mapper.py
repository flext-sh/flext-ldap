#!/usr/bin/env python3
"""Map dependencies between flext-ldap and client-a-oud-mig."""

from pathlib import Path


def find_flext_ldap_usage_in_client-a() -> None:
    """Find all flext-ldap usage in client-a-oud-mig."""
    client-a_path = Path("../client-a-oud-mig")

    if not client-a_path.exists():
        print("⚠️  client-a-oud-mig not found at expected location: ../client-a-oud-mig")
        print("Skipping client-a-oud-mig dependency analysis")
        return

    print("\n" + "=" * 100)
    print("FLEXT-LDAP IMPORTS IN client-a-OUD-MIG")
    print("=" * 100 + "\n")

    # Find all imports from flext_ldap using native Python file operations
    imports: list[str] = []
    try:
        for py_file in client-a_path.rglob("*.py"):
            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore")
                if "from flext_ldap import" in content:
                    imports.extend(
                        f"{py_file}: {line.strip()}"
                        for line in content.split("\n")
                        if "from flext_ldap import" in line
                    )
            except OSError:
                pass

        if imports:
            for imp in sorted(imports):
                print(imp)
        else:
            print("No imports found")

    except Exception as e:
        print(f"Error searching: {e}")

    print("\n" + "=" * 100)
    print("FlextLdapModels USAGE IN client-a-OUD-MIG")
    print("=" * 100 + "\n")

    # Find all usages of FlextLdapModels using native Python file operations
    usages: list[str] = []
    try:
        for py_file in client-a_path.rglob("*.py"):
            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore")
                if "FlextLdapModels" in content:
                    usages.extend(
                        f"{py_file}: {line.strip()}"
                        for line in content.split("\n")
                        if "FlextLdapModels" in line
                    )
            except OSError:
                pass

        if usages:
            for usage in sorted(usages):
                print(usage)
        else:
            print("No FlextLdapModels usage found")

    except Exception as e:
        print(f"Error searching: {e}")


if __name__ == "__main__":
    find_flext_ldap_usage_in_client-a()

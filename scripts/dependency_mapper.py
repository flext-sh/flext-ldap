#!/usr/bin/env python3
"""Map dependencies between flext-ldap and client-a-oud-mig."""

import subprocess
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

    # Find all imports from flext_ldap
    try:
        result = subprocess.run(
            ["grep", "-r", "from flext_ldap import", str(client-a_path), "--include=*.py"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )

        imports = [line.strip() for line in result.stdout.split("\n") if line.strip()]

        if imports:
            for imp in sorted(imports):
                print(imp)
        else:
            print("No imports found")

    except subprocess.TimeoutExpired:
        print("Search timeout")
    except Exception as e:
        print(f"Error searching: {e}")

    print("\n" + "=" * 100)
    print("FlextLdapModels USAGE IN client-a-OUD-MIG")
    print("=" * 100 + "\n")

    try:
        result = subprocess.run(
            ["grep", "-r", "FlextLdapModels", str(client-a_path), "--include=*.py"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )

        usages = [line.strip() for line in result.stdout.split("\n") if line.strip()]

        if usages:
            for usage in sorted(usages):
                print(usage)
        else:
            print("No FlextLdapModels usage found")

    except subprocess.TimeoutExpired:
        print("Search timeout")
    except Exception as e:
        print(f"Error searching: {e}")


if __name__ == "__main__":
    find_flext_ldap_usage_in_client-a()

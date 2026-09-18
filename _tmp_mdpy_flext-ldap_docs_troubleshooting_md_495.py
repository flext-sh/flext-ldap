# from flext-ldap_docs/troubleshooting.md:495
from __future__ import annotations

import os
from Flext_ldap import FlextLdapSettings


def diagnose_config():
    """Check configuration values."""
    settings = FlextLdapSettings.from_env()

    print("LDAP Configuration:")
    print(f"  Host: {settings.host}")
    print(f"  Port: {settings.port}")
    print(f"  Use SSL: {settings.use_ssl}")
    print(f"  Bind DN: {settings.bind_dn}")
    print(f"  Base DN: {settings.base_dn}")

    # Check environment variables
    env_vars = [
        "FLEXT_LDAP_HOST",
        "FLEXT_LDAP_PORT",
        "FLEXT_LDAP_BIND_DN",
        "FLEXT_LDAP_BIND_PASSWORD",
        "FLEXT_LDAP_BASE_DN",
    ]

    print("\nEnvironment Variables:")
    for var in env_vars:
        value = os.getenv(var)
        if var == "FLEXT_LDAP_BIND_PASSWORD":
            value = "***" if value else None
        print(f"  {var}: {value}")


diagnose_config()```
### Docker Environment Issues

**Common Docker Problems:**

1. **Service name resolution:**


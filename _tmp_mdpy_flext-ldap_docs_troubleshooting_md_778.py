# from flext-ldap_docs/troubleshooting.md:778
from __future__ import annotations

import sys
import pkg_resources
from Flext_ldap import FlextLdapSettings


def collect_diagnostic_info():
    """Collect diagnostic information for bug reports."""
    print("=== FLEXT-LDAP Diagnostic Information ===")

    # System information
    print(f"Python version: {sys.version}")
    print(f"Platform: {sys.platform}")

    # Package versions
    packages = ["flext-ldap", "flext-core", "ldap3", "pydantic"]
    for package in packages:
        try:
            version = pkg_resources.get_distribution(package).version
            print(f"{package}: {version}")
        except pkg_resources.DistributionNotFound:
            print(f"{package}: Not installed")

    # Configuration (sanitized)
    try:
        settings = FlextLdapSettings.from_env()
        print(f"LDAP Host: {settings.host}")
        print(f"LDAP Port: {settings.port}")
        print(f"Use SSL: {settings.use_ssl}")
        print(f"Base DN: {settings.base_dn}")
        print("Bind credentials: [CONFIGURED]")
    except Exception as e:
        print(f"Configuration error: {e}")


collect_diagnostic_info()```
______________________________________________________________________

For additional support and community resources:

- [GitHub Issues](https://github.com/flext-sh/flext-ldap/issues) - Bug reports and feature requests
- [FLEXT Documentation](https://docs.flext.dev) - Framework documentation
- Examples - Working code examples

______________________________________________________________________

**Previous:** Integration Guide ←

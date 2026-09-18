# from flext-ldap_docs/troubleshooting.md:575
# Check package installation
import pkg_resources

try:
    version = pkg_resources.get_distribution("flext-ldap").version
    print(f"flext-ldap version: {version}")
except pkg_resources.DistributionNotFound:
    print("flext-ldap not installed")

# Check available imports
try:
    from flext_ldap.api import ldap

    print("✅ flext_ldap.api.ldap available")
except ImportError as e:
    print(f"❌ Import error: {e}")

try:
    from flext_ldap import FlextLdapEntities

    print("✅ FlextLdapEntities available")
except ImportError as e:
    print(f"❌ Import error: {e}")```
### Test Environment Setup

**Docker LDAP Server Issues:**


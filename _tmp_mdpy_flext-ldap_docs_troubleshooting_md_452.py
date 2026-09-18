# from flext-ldap_docs/troubleshooting.md:452
# Check connection pool configuration
from Flext_ldap import FlextLdapSettings

settings = FlextLdapSettings.from_env()
print(f"Pool size: {settings.pool_size}")
print(f"Connection timeout: {settings.connection_timeout}")```
**Solutions:**

1. **Increase pool size:**


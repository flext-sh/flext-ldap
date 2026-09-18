# from flext-ldap/docs/configuration.md:326
# Use environment variables for secrets
import os

settings = FlextLdapSettings(
    host=os.getenv("FLEXT_LDAP_HOST"),
    bind_password=os.getenv("FLEXT_LDAP_BIND_PASSWORD"),
    # ... other settings
)```
### SSL/TLS Configuration


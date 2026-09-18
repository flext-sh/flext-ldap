# from flext-ldap/docs/configuration.md:282
from __future__ import annotations

from flext_ldap.api import ldap


def validate_config():
    """Validate LDAP configuration."""
    api = ldap

    result = api.test_connection()
    if result.success:
        print("✅ Configuration valid - LDAP connection successful")
    else:
        print(f"❌ Configuration invalid: {result.error}")


run(validate_config())```
### Common Configuration Issues

**Connection Refused:**

- Check host and port settings
- Verify firewall allows LDAP traffic (389/636)
- Confirm LDAP server is running

**Authentication Failed:**

- Verify bind DN format (RFC 4514 compliant)
- Check bind password
- Ensure service account has appropriate permissions

**SSL/TLS Errors:**

- Verify certificate chain
- Check CA certificate file path
- Confirm SSL port (usually 636)

______________________________________________________________________

## Security Best Practices

### Credential Management


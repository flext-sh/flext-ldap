# from flext-ldap/docs/api-reference.md:387
from Flext_ldap import FlextLdapSettings, set_flext_ldap.settings

settings = FlextLdapSettings(
    host="ldap.example.com",
    port=636,
    use_ssl=True,
    bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
    bind_password="REDACTED_LDAP_BIND_PASSWORD-password",
    base_dn="dc=example,dc=com"
)

set_flext_ldap.settings(settings)```
______________________________________________________________________

## 🔧 Utilities

### FlextLdapTypeGuards

Type guard functions for runtime type checking.

#### `is_valid_dn(value: str) -> bool`

Check if string is a valid distinguished name.

**Example:**


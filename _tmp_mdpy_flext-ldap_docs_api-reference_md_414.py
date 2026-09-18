# from flext-ldap_docs/api-reference.md:414
from flext_ldap import FlextLdapTypeGuards

if FlextLdapTypeGuards.is_valid_dn("cn=user,dc=example,dc=com"):
    print("Valid DN")```
#### `is_ldap_entry(obj) -> bool`

Check if t.JsonValue is a valid LDAP entry.

### FlextLdapConstants

LDAP protocol constants.

**Attributes:**

- `DEFAULT_PORT`: Default LDAP port (389)
- `DEFAULT_SSL_PORT`: Default LDAPS port (636)
- `SCOPE_BASE`: Base search scope
- `SCOPE_ONELEVEL`: One-level search scope
- `SCOPE_SUBTREE`: Subtree search scope

______________________________________________________________________

## 🚨 Exceptions

### e

LDAP-specific exception classes.

#### ConnectionError

Connection-related errors.

**Attributes:**

- `message` (str): Error description
- `server` (str, optional): LDAP server address

#### AuthenticationError

Authentication failures.

**Attributes:**

- `message` (str): Error description
- `username` (str, optional): Failed username

#### SearchError

Search operation errors.

**Attributes:**

- `message` (str): Error description
- `base_dn` (str, optional): Search base DN
- `filter_str` (str, optional): Search filter

**Example:**


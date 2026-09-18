# from flext-ldap_docs/api-reference.md:349
# Create filters
user_filter = FlextLdapModels.Values.LdapFilter.equals("uid", "john.doe")
person_filter = FlextLdapModels.Values.LdapFilter.object_class("person")

# Combine filters
combined = FlextLdapModels.Values.LdapFilter.and_filters(user_filter, person_filter)```
#### LdapScope

Search scope enumeration.

**Values:**

- `BASE`: Search base t.JsonValue only
- `ONELEVEL`: Search immediate children
- `SUBTREE`: Search entire subtree

______________________________________________________________________

## ⚙️ Configuration

### FlextLdapSettings

LDAP connection configuration.

**Attributes:**

- `host` (str): LDAP server hostname
- `port` (int): LDAP server port (default: 389)
- `use_ssl` (bool): Use SSL connection (default: False)
- `bind_dn` (str): Bind distinguished name
- `bind_password` (str): Bind password
- `base_dn` (str): Base distinguished name
- `timeout` (int): Connection timeout in seconds (default: 30)
- `pool_size` (int): Connection pool size (default: 5)

**Example:**


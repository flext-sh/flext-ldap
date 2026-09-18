# from flext-ldap_docs/api-reference.md:328
dn = FlextLdapModels.Values.DN("cn=user,ou=people,dc=example,dc=com")
print(dn.rdn)  # "cn=user"
print(dn.parent_dn)  # "ou=people,dc=example,dc=com"```
#### LdapFilter

LDAP search filter with validation.

**Attributes:**

- `expression` (str): Filter expression

**Class Methods:**

- `equals(attribute: str, value: str) -> LdapFilter`: Create equality filter
- `object_class(object_class: str) -> LdapFilter`: Create objectClass filter
- `and_filters(*filters) -> LdapFilter`: Combine filters with AND
- `or_filters(*filters) -> LdapFilter`: Combine filters with OR

**Example:**


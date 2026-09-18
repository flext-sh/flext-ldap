# from flext-ldap_docs/api-reference.md:834
new_acls = [
    {"raw": '{0}to * by dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com" write'},
    {"raw": "{1}to * by self write by anonymous auth"},
]

result = ops.set_acls(connection, dn, acls=new_acls)```
##### `parse(acl_string) -> p.Result[m.Dict]`

Parse server-specific ACL string to dictionary.

##### `format_acl(acl_dict) -> p.Result[str]`

Format ACL dictionary to server-specific string.

#### Entry Operations

##### `add_entry(connection, entry) -> p.Result[bool]`

Add ldif entry to directory.

**Example:**


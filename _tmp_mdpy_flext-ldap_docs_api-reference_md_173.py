# from flext-ldap_docs/api-reference.md:173
search_request = FlextLdapEntities.SearchRequest(
    base_dn="dc=example,dc=com",
    filter_str="(objectClass=person)",
    scope="subtree",
    attributes=["uid", "cn", "mail"],
)

result = api.search_entries(search_request)
if result.success:
    entries = result.unwrap()```
### `authenticate_user(username: str, password: str) -> p.Result[FlextLdapUser]`

Authenticate user credentials against LDAP directory.

**Parameters:**

- `username` (str): User identifier
- `password` (str): User password

**Returns:** r containing authenticated user t.JsonValue

**Example:**


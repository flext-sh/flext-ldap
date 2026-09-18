# from flext-ldap/docs/api-reference.md:214
user_request = FlextLdapEntities.CreateUserRequest(
    dn="cn=jane.doe,ou=users,dc=example,dc=com",
    uid="jane.doe",
    cn="Jane Doe",
    sn="Doe",
    mail="jane.doe@example.com",
)

result = api.create_user(user_request)```
### `test_connection() -> p.Result[str]`

Test LDAP server connectivity.

**Returns:** r with connection status message

**Example:**


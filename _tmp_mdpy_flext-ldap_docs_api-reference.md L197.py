# from flext-ldap/docs/api-reference.md:197
result = api.authenticate_user("john.doe", "password123")
if result.success:
    user = result.unwrap()
    print(f"Authenticated: {user.cn}")```
### `create_user(request: CreateUserRequest) -> p.Result[FlextLdapUser]`

Create a new user in LDAP directory.

**Parameters:**

- `request`: CreateUserRequest with user details

**Returns:** r containing created user t.JsonValue

**Example:**


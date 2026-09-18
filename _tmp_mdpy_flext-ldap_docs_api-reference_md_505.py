# from flext-ldap_docs/api-reference.md:505
result = api.authenticate_user(username, password)

if result.failure:
    error_message = result.error
    print(f"Authentication failed: {error_message}")```
### Chaining Operations


# from flext-ldap/docs/guides/universal-ldap-guide.md:434
# Good: Detect before operations
server_type_result = api.get_detected_server_type()
if server_type_result.success:
    server_type = server_type_result.unwrap()
    # Use server_type for operations```
### 2. Validate After Conversion


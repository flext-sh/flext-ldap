# from flext-ldap_docs/guides/acl-management.md:337
# All operations return r for safe error handling
result = api.parse(acl_string, format_type)

if result.failure:
    print(f"Error: {result.error}")
    # Handle error appropriately
else:
    unified_acl = result.unwrap()
    # Process successful result```
## Integration with FLEXT OUD Migration


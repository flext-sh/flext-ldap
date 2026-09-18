# from flext-ldap/docs/guides/universal-ldap-guide.md:454
# Good: Check capabilities before operations
caps_result = api.get_server_capabilities()
if caps_result.success:
    caps = caps_result.unwrap()

    if caps["supports_paged_results"]:
        # Use paged search
        api.search_universal(..., use_paging=True)```
### 4. Handle Servers Gracefully


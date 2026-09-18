# from flext-ldap/docs/api-reference.md:513
search_result = api.search_entries(request)
if search_result.success:
    entries = search_result.unwrap()
    # Process entries...
else:
    # Handle search failure
    return r.fail(f"Search failed: {search_result.error}")```
______________________________________________________________________

## 🔄 Universal LDAP Interface

### FlextLdapEntryAdapter

Bidirectional converter between ldap3 entries and ldif entries.

**Import:**


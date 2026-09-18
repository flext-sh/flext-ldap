# from flext-ldap/docs/guides/server-operations.md:664
servers = FlextLdapServersAdapter()
server_type_result = servers.detect_server_type_from_entries(entries)

if server_type_result.success:
    server_type = server_type_result.unwrap()
    # Select appropriate operations class```
### **2. Handle Errors Explicitly**

All operations return `r` - always check for failures:


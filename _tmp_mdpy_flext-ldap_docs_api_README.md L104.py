# from flext-ldap/docs/api/README.md:104
acl_manager = FlextLdapAcl.Manager()
result = acl_manager.get_acls(connection, dn, server_type)```
## API Stability

### Stable (Public API)

- ✅ ldap - Main API facade
- ✅ FlextLdapModels - Domain models
- ✅ FlextLdapClients - Client operations
- ✅ FlextLdapAcl - ACL management

### Internal (Subject to Change)

- ⚠️ FlextLdapServices - Internal business logic
- ⚠️ FlextLdapHandlers - Internal handlers
- ⚠️ Server operations - May evolve with new features

## Return Types

All operations return `r[T]` from flext-core:


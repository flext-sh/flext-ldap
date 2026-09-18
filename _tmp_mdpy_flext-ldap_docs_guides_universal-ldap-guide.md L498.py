# from flext-ldap/docs/guides/universal-ldap-guide.md:498
caps_result = api.get_server_capabilities()
if caps_result.success:
    caps = caps_result.unwrap()
    print(f"ACL format: {caps['acl_format']}")
    print(f"ACL attribute: {caps['acl_attribute']}")```
## Contributing

To add support for additional LDAP servers:

1. Create new server operations class inheriting from `BaseServerOperations`
1. Implement all required methods (connection, schema, ACL, entry, search)
1. Add server-specific servers to ldif servers system
1. Register in `ServerOperationsFactory`
1. Add tests and documentation

See `src/flext_ldap/servers/ad_operations.py` for stub template.

______________________________________________________________________

**Copyright (c) 2025 FLEXT Team. All rights reserved.**
**SPDX-License-Identifier: MIT**

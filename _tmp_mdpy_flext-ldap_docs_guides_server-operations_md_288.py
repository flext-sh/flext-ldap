# from flext-ldap_docs/guides/server-operations.md:288
# Large result set with paging
search_result = ops.search_with_paging(
    connection,
    base_dn="dc=example,dc=com",
    search_filter="(objectClass=person)",
    attributes=["cn", "mail", "sn"],
    page_size=100,
)

if search_result.success:
    entries = search_result.unwrap()
    print(f"Found {len(entries)} entries")

    for entry in entries:
        print(f"DN: {entry.dn}")
        print(f"Attributes: {entry.attributes}")```
##

## 🔧 OpenLDAP 1.x Operations

### **Features**

- **slapd.conf** static configuration
- **access** ACL syntax (legacy)
- Inherits most functionality from OpenLDAP 2.x
- Limited VLV support

### **Key Differences**


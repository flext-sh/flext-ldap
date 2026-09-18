# from flext-ldap_docs/getting-started.md:334
from flext_ldap import FlextLdapEntryAdapter
from flext_ldif import FlextLdifModels

adapter = FlextLdapEntryAdapter()

# ldap3 → ldif
connection.search("dc=example,dc=com", "(objectClass=person)")
for ldap3_entry in connection.entries:
    ldif_result = adapter.ldap3_to_ldif_entry(ldap3_entry)
    if ldif_result.success:
        ldif_entry = ldif_result.unwrap()
        print(f"DN: {ldif_entry.dn}")

# ldif → ldap3
ldif_entry = FlextLdifModels.Entry(
    dn=FlextLdifModels.DN(value="cn=test,dc=example,dc=com"),
    attributes=FlextLdifModels.Attributes(
        attributes={"objectClass": ["person"], "cn": ["test"], "sn": ["Test User"]}
    ),
)

attrs_result = adapter.ldif_entry_to_ldap3_attributes(ldif_entry)
if attrs_result.success:
    attributes = attrs_result.unwrap()
    connection.add(str(ldif_entry.dn), attributes=attributes)```
### **Schema Discovery**

Discover schema from different LDAP server types:


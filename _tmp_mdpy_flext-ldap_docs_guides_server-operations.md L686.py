# from flext-ldap/docs/guides/server-operations.md:686
adapter = FlextLdapEntryAdapter()

# ldap3 → ldif
ldif_result = adapter.ldap3_to_ldif_entry(ldap3_entry)

# ldif → ldap3
attrs_result = adapter.ldif_entry_to_ldap3_attributes(ldif_entry)```
### **4. Server-Specific Normalization**

Each server may require specific entry normalization:


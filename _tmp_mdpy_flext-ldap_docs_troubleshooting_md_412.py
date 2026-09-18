# from flext-ldap_docs/troubleshooting.md:412
# ❌ Inefficient - searches entire directory
search_request = FlextLdapEntities.SearchRequest(
    base_dn="dc=example,dc=com", filter_str="(uid=john.doe)", scope="subtree"
)

# ✅ Efficient - searches specific branch
search_request = FlextLdapEntities.SearchRequest(
    base_dn="ou=users,dc=example,dc=com", filter_str="(uid=john.doe)", scope="onelevel"
)```
1. **Optimize search filters:**


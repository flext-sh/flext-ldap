# from flext-ldap/docs/api/README.md:91
api = ldap()
search_request = FlextLdapModels.SearchRequest(
    base_dn="dc=example,dc=com", filter_str="(objectClass=person)"
)
result = api.search_entries(search_request)```
**Authentication**:


# from flext-ldap/docs/development.md:684
# Optimize LDAP searches
search_request = FlextLdapEntities.SearchRequest(
    base_dn="ou=users,dc=example,dc=com",  # Use specific base DN
    filter_str="(&(objectClass=person)(uid=j*))",  # Indexed attributes
    scope="onelevel",  # Minimal scope needed
    attributes=["uid", "cn"],  # Only required attributes
    size_limit=50,  # Reasonable page size
    time_limit=10,  # Prevent long-running searches
)```
### Best Practices


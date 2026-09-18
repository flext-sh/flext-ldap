# from flext-ldap/docs/troubleshooting.md:435
search_request = FlextLdapEntities.SearchRequest(
    base_dn="ou=users,dc=example,dc=com",
    filter_str="(objectClass=person)",
    scope="subtree",
    attributes=["uid", "cn"],  # Only needed attributes
    size_limit=100,  # Reasonable limit
    time_limit=10,  # Prevent long-running queries
)```
### Connection Pool Exhaustion

**Symptoms:**


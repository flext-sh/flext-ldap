# from flext-ldap/docs/configuration.md:361
from flext_ldap import FlextLdapEntities

# Optimized search request
search_request = FlextLdapEntities.SearchRequest(
    base_dn="ou=users,dc=example,dc=com",
    filter_str="(&(objectClass=person)(uid=*))",
    scope="onelevel",  # Use minimal scope needed
    attributes=["uid", "cn"],  # Request only needed attributes
    size_limit=100,  # Limit result size
    time_limit=10,  # Set search timeout
)```
______________________________________________________________________

For more configuration examples, see the examples/ directory.

______________________________________________________________________

**Next:** Development Guide →

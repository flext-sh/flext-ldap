# from flext-ldap/docs/guides/server-operations.md:745
# Reduce page size
result = ops.search_with_paging(
    connection,
    base_dn,
    search_filter,
    page_size=50,  # Smaller page size
)```
**Entry Addition Fails**:


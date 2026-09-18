# from flext-ldap/docs/guides/universal-ldap-guide.md:169
# Universal search with automatic server-specific optimization
result = api.search_universal(
    base_dn="ou=users,dc=example,dc=com",
    filter_str="(objectClass=person)",
    attributes=["uid", "cn", "mail", "sn"],
    use_paging=True,  # Automatically uses server's best paging method
)

if result.success:
    entries = result.unwrap()
    print(f"Found {len(entries)} entries")
    for entry in entries:
        print(f"DN: {entry.dn}")```
### 4. Entry Normalization


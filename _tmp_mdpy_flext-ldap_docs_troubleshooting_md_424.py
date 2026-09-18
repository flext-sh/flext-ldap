# from flext-ldap_docs/troubleshooting.md:424
# ❌ Inefficient - broad filter
filter_str = "(cn=*john*)"

# ✅ Efficient - indexed attribute with specific value
filter_str = "(uid=john.doe)"

# ✅ Efficient - compound filter with indexed attributes
filter_str = "(&(objectClass=person)(uid=john.doe))"```
1. **Limit result sets:**


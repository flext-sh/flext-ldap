# from flext-ldap_docs/guides/server-operations.md:698
norm_result = ops.normalize_entry(entry)
if norm_result.success:
    normalized_entry = norm_result.unwrap()
    # Use normalized entry```
### **5. Connection Management**

Proper connection lifecycle:


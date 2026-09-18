# from flext-ldap_docs/guides/server-operations.md:675
result = ops.add_entry(connection, entry)
if result.failure:
    print(f"Operation failed: {result.error}")
    # Handle error appropriately
else:
    print("Operation succeeded")```
### **3. Use Entry Adapter**

Always use the Entry Adapter for conversions:


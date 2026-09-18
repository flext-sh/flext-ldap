# from flext-ldap/docs/guides/server-operations.md:707
# Create connection
connection = ldap3.Connection(...)
connection.bind()

try:
    # Operations
    result = ops.add_entry(connection, entry)
finally:
    # Always unbind
    connection.unbind()```
##

## 🔧 Troubleshooting

### **Common Issues**

**Schema Discovery Fails**:


# from flext-ldap/docs/troubleshooting.md:463
settings = FlextLdapSettings(
    host="ldap.example.com",
    pool_size=20,  # Increase from default 5
    connection_timeout=10,
    receive_timeout=30,
)```
1. **Implement connection reuse:**


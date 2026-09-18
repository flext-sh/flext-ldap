# from flext-ldap/docs/configuration.md:351
# High-traffic configuration
settings = FlextLdapSettings(
    pool_size=20,  # Adjust based on concurrent users
    connection_timeout=FlextLdapConstants.LdapRetry.CONNECTION_RETRY_DELAY,  # Fast connection timeout
    receive_timeout=FlextLdapConstants.LdapRetry.SERVER_READY_TIMEOUT,  # Operation timeout
    max_retries=2,  # Retry failed operations
)```
### Search Optimization


# from flext-ldap/docs/configuration.md:337
settings = FlextLdapSettings(
    host="ldap.example.com",
    port=FlextConstants.LDAPS_DEFAULT_PORT,
    use_ssl=True,
    ca_cert_file="/etc/ssl/certs/ca-bundle.pem",
    verify_certs=True,
)```
______________________________________________________________________

## Performance Tuning

### Connection Pool Optimization


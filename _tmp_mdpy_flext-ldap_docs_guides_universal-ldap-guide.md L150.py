# from flext-ldap/docs/guides/universal-ldap-guide.md:150
# Get comprehensive server capabilities
caps_result = api.get_server_capabilities()
if caps_result.success:
    caps = caps_result.unwrap()

    print(f"Server type: {caps['server_type']}")
    print(f"ACL format: {caps['acl_format']}")
    print(f"ACL attribute: {caps['acl_attribute']}")
    print(f"Schema DN: {caps['schema_dn']}")
    print(f"Default port: {caps['default_port']}")
    print(f"SSL port: {caps['default_ssl_port']}")
    print(f"Supports START_TLS: {caps['supports_start_tls']}")
    print(f"BIND mechanisms: {caps['bind_mechanisms']}")
    print(f"Max page size: {caps['max_page_size']}")
    print(f"Paged results: {caps['supports_paged_results']}")
    print(f"VLV support: {caps['supports_vlv']}")```
### 3. Universal Search with Optimization


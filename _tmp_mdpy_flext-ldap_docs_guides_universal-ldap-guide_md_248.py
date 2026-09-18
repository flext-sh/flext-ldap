# from flext-ldap_docs/guides/universal-ldap-guide.md:248
# Get server-specific attribute information
attrs_result = api.get_server_specific_attributes("oid")
if attrs_result.success:
    attrs = attrs_result.unwrap()
    print(f"Required attributes: {attrs.get('required_attributes', [])}")
    print(f"Optional attributes: {attrs.get('optional_attributes', [])}")```
## Entry Conversion Examples

### OpenLDAP 1.x → OpenLDAP 2.x Migration


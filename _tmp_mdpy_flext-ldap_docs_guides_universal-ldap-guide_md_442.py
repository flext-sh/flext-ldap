# from flext-ldap_docs/guides/universal-ldap-guide.md:442
# Good: Validate converted entries
convert_result = api.convert_entry_between_servers(...)
if convert_result.success:
    entry = convert_result.unwrap()

    validation_result = api.validate_entry_for_server(entry, target_type)
    if validation_result.success and validation_result.unwrap():
        # Proceed with entry
        pass```
### 3. Use Server Capabilities


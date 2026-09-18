# from flext-ldap_docs/guides/universal-ldap-guide.md:489
# Validate source entry
validation_result = api.validate_entry_for_server(entry, source_type)
if validation_result.failure:
    print(f"Source entry invalid: {validation_result.error}")```
### ACL Translation Issues

Different servers have different ACL formats. Check server capabilities:


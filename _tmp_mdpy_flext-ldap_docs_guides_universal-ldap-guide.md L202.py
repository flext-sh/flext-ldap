# from flext-ldap/docs/guides/universal-ldap-guide.md:202
from __future__ import annotations

# Convert entry from OpenLDAP 1.x to OpenLDAP 2.x
openldap1_entry: FlextLdifModels.Entry = ...  # Entry from OpenLDAP 1.x

convert_result = api.convert_entry_between_servers(
    entry=openldap1_entry,
    source_server_type="openldap1",
    target_server_type="openldap2",
)

if convert_result.success:
    openldap2_entry = convert_result.unwrap()
    # Entry now has:
    # - olcAccess instead of access
    # - Converted objectClasses
    # - Adjusted ACL format```
### 6. Server Type Detection


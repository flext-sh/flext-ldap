# from flext-ldap/docs/guides/universal-ldap-guide.md:185
from __future__ import annotations

from flext_ldif import FlextLdifModels

# Normalize entry for current server
entry: FlextLdifModels.Entry = ...  # Your entry
normalized_result = api.normalize_entry_for_server(entry)

if normalized_result.success:
    normalized_entry = normalized_result.unwrap()
    print("Entry normalized for current server")

# Normalize for specific target server
normalized_result = api.normalize_entry_for_server(entry, target_server_type="oud")```
### 5. Entry Conversion Between Servers


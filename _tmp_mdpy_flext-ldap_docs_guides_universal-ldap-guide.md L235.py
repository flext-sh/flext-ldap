# from flext-ldap/docs/guides/universal-ldap-guide.md:235
from __future__ import annotations

# Validate entry for target server
entry: FlextLdifModels.Entry = ...

validation_result = api.validate_entry_for_server(entry, "oud")
if validation_result.success and validation_result.unwrap():
    print("Entry is compatible with Oracle OUD")
else:
    print(f"Validation failed: {validation_result.error}")```
### 8. Server-Specific Attributes


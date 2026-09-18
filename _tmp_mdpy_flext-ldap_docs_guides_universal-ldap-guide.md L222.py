# from flext-ldap/docs/guides/universal-ldap-guide.md:222
from __future__ import annotations

# Detect server type from entry attributes
unknown_entry: FlextLdifModels.Entry = ...  # Entry from unknown source

detection_result = api.detect_entry_server_type(unknown_entry)
if detection_result.success:
    detected_type = detection_result.unwrap()
    print(f"Entry originated from: {detected_type}")
    # Output: "openldap2", "oud", "oid", etc.```
### 7. Entry Validation


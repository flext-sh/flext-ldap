# from flext-ldap_docs/guides/universal-ldap-guide.md:377
from __future__ import annotations


def progressive_migration():
    """Gradually migrate from old to new LDAP server."""
    api = ldap()

    # Phase 1: Analyze source entries
    source_entries = []  # Load from source

    server_types = {}
    for entry in source_entries:
        detection_result = api.detect_entry_server_type(entry)
        if detection_result.success:
            detected_type = detection_result.unwrap()
            server_types[detected_type] = server_types.get(detected_type, 0) + 1

    print(f"Entry distribution: {server_types}")

    # Phase 2: Convert in batches
    target_type = "oud"
    converted_batches = []

    batch_size = 100
    for i in range(0, len(source_entries), batch_size):
        batch = source_entries[i : i + batch_size]
        converted_batch = []

        for entry in batch:
            source_type = api.detect_entry_server_type(entry).unwrap()

            if source_type != target_type:
                convert_result = api.convert_entry_between_servers(
                    entry=entry,
                    source_server_type=source_type,
                    target_server_type=target_type,
                )

                if convert_result.success:
                    converted_batch.append(convert_result.unwrap())
            else:
                converted_batch.append(entry)

        converted_batches.append(converted_batch)
        print(f"Converted batch {i // batch_size + 1}")

    # Phase 3: Validate all entries
    for batch in converted_batches:
        for entry in batch:
            validation_result = api.validate_entry_for_server(entry, target_type)
            if validation_result.failure or not validation_result.unwrap():
                print(f"Validation failed for {entry.dn}")```
## Best Practices

### 1. Always Detect Server Type


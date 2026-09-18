# from flext-ldap/docs/api-reference.md:884
modifications = {"mail": ["newemail@example.com"], "telephoneNumber": ["+1-555-0100"]}

result = ops.modify_entry(
    connection, dn="cn=test,dc=example,dc=com", modifications=modifications
)```
##### `delete_entry(connection, dn) -> p.Result[bool]`

Delete entry from directory.

##### `normalize_entry(entry) -> p.Result[FlextLdifModels.Entry]`

Normalize entry for server-specific requirements.

#### Search Operations

##### `get_max_page_size() -> int`

Get maximum page size for paged searches.

##### `supports_paged_results() -> bool`

Check if server supports paged results control.

##### `supports_vlv() -> bool`

Check if server supports Virtual List View (VLV).

##### `search_with_paging(connection, base_dn, search_filter, attributes=None, page_size=100) -> p.Result[Sequence[FlextLdifModels.Entry]]`

Execute paged search with automatic pagination.

**Example:**


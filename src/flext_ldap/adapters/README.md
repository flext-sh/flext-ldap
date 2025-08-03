# Adapters Layer - FLEXT-LDAP

The adapters layer implements interface adapters that connect FLEXT-LDAP with external systems and protocols, following Clean Architecture principles for external system integration.

## Architecture Principles

This layer serves as the translation boundary:
- **Protocol adaptation**: Converts between domain models and external formats
- **System integration**: Adapts to external APIs and data formats
- **Interface implementation**: Implements external system contracts
- **Data format conversion**: Handles serialization/deserialization

## Module Structure

```
adapters/
├── __init__.py              # Adapter layer exports
├── directory_adapter.py     # Directory service protocol adapter
└── singer_adapter.py        # Singer/Meltano ecosystem integration (planned)
```

## Directory Service Adapter

### FlextLdapDirectoryAdapter
Primary adapter for directory service operations:

```python
class FlextLdapDirectoryAdapter:
    """Adapter for external directory service integration."""
    
    def __init__(self, config: FlextLdapDirectoryConfig):
        self._config = config
        self._connection_manager = FlextLdapConnectionManager(config)
    
    async def search_entries(
        self,
        base_dn: FlextLdapDistinguishedName,
        filter_spec: FlextLdapFilter,
        scope: FlextLdapSearchScope
    ) -> FlextResult[list[FlextLdapEntry]]:
        """Search directory entries with domain object conversion."""
        
    async def create_entry(
        self,
        entry: FlextLdapEntry
    ) -> FlextResult[bool]:
        """Create directory entry from domain object."""
```

Key responsibilities:
- **Domain-to-Protocol Conversion**: Converts domain objects to LDAP protocol format
- **Error Translation**: Maps LDAP protocol errors to domain errors
- **Connection Management**: Manages LDAP connection lifecycle
- **Result Transformation**: Converts LDAP responses to domain entities

### Protocol Conversion Examples

#### Domain to LDAP Conversion
```python
def _convert_domain_entry_to_ldap(
    self,
    entry: FlextLdapEntry
) -> dict[str, Any]:
    """Convert domain entry to LDAP protocol format."""
    
    ldap_attributes = {}
    
    # Convert domain attributes to LDAP format
    for attr_name, attr_values in entry.attributes.items():
        if isinstance(attr_values, list):
            ldap_attributes[attr_name] = [str(v) for v in attr_values]
        else:
            ldap_attributes[attr_name] = [str(attr_values)]
    
    # Ensure required object classes
    if 'objectClass' not in ldap_attributes:
        ldap_attributes['objectClass'] = entry.object_classes
    
    return {
        'dn': entry.dn,
        'attributes': ldap_attributes
    }
```

#### LDAP to Domain Conversion
```python
def _convert_ldap_result_to_domain(
    self,
    ldap_result: dict[str, Any]
) -> FlextLdapEntry:
    """Convert LDAP search result to domain entity."""
    
    # Extract DN
    dn = ldap_result.get('dn', '')
    
    # Extract attributes
    raw_attributes = ldap_result.get('attributes', {})
    formatted_attributes = {}
    
    for attr_name, attr_values in raw_attributes.items():
        if isinstance(attr_values, list):
            formatted_attributes[attr_name] = [str(v) for v in attr_values]
        else:
            formatted_attributes[attr_name] = [str(attr_values)]
    
    # Extract object classes
    object_classes = formatted_attributes.get('objectClass', [])
    
    return FlextLdapEntry(
        id=str(uuid4()),
        dn=dn,
        object_classes=object_classes,
        attributes=formatted_attributes
    )
```

## Singer Ecosystem Integration (Planned)

### FlextLdapSingerAdapter
Integration with Singer/Meltano data pipeline ecosystem:

```python
class FlextLdapSingerAdapter:
    """Adapter for Singer tap/target integration."""
    
    def __init__(self, ldap_api: FlextLdapApi):
        self._ldap_api = ldap_api
        self._catalog_generator = FlextLdapCatalogGenerator()
    
    async def discover_catalog(self) -> FlextResult[SingerCatalog]:
        """Discover LDAP schema and generate Singer catalog."""
        
    async def extract_records(
        self,
        catalog: SingerCatalog,
        state: SingerState
    ) -> AsyncIterator[SingerMessage]:
        """Extract LDAP records as Singer messages."""
        
    async def load_records(
        self,
        messages: AsyncIterator[SingerMessage]
    ) -> FlextResult[LoadResult]:
        """Load Singer messages to LDAP directory."""
```

### Singer Message Conversion

#### LDAP to Singer Message
```python
def _convert_ldap_entry_to_singer_record(
    self,
    entry: FlextLdapEntry,
    stream_name: str
) -> SingerRecord:
    """Convert LDAP entry to Singer record format."""
    
    record_data = {
        'dn': entry.dn,
        'object_classes': entry.object_classes
    }
    
    # Flatten LDAP attributes to Singer format
    for attr_name, attr_values in entry.attributes.items():
        if len(attr_values) == 1:
            record_data[attr_name] = attr_values[0]
        else:
            record_data[attr_name] = attr_values
    
    return SingerRecord(
        stream=stream_name,
        record=record_data,
        time_extracted=datetime.utcnow()
    )
```

#### Singer Message to LDAP
```python
def _convert_singer_record_to_ldap_entry(
    self,
    record: SingerRecord
) -> FlextLdapEntry:
    """Convert Singer record to LDAP entry."""
    
    record_data = record.record
    
    # Extract DN and object classes
    dn = record_data.pop('dn', '')
    object_classes = record_data.pop('object_classes', [])
    
    # Convert remaining fields to LDAP attributes
    attributes = {}
    for field_name, field_value in record_data.items():
        if isinstance(field_value, list):
            attributes[field_name] = [str(v) for v in field_value]
        else:
            attributes[field_name] = [str(field_value)]
    
    return FlextLdapEntry(
        id=str(uuid4()),
        dn=dn,
        object_classes=object_classes,
        attributes=attributes
    )
```

## Data Format Adapters

### LDIF Format Adapter
Integration with LDIF (LDAP Data Interchange Format):

```python
class FlextLdapLdifAdapter:
    """Adapter for LDIF format conversion."""
    
    def convert_entries_to_ldif(
        self,
        entries: list[FlextLdapEntry]
    ) -> str:
        """Convert domain entries to LDIF format."""
        
    def parse_ldif_to_entries(
        self,
        ldif_content: str
    ) -> FlextResult[list[FlextLdapEntry]]:
        """Parse LDIF content to domain entries."""
```

### JSON/REST API Adapter
REST API integration for web services:

```python
class FlextLdapRestAdapter:
    """Adapter for REST API integration."""
    
    def convert_entry_to_json(
        self,
        entry: FlextLdapEntry
    ) -> dict[str, Any]:
        """Convert domain entry to JSON format."""
        
    def parse_json_to_entry(
        self,
        json_data: dict[str, Any]
    ) -> FlextResult[FlextLdapEntry]:
        """Parse JSON data to domain entry."""
```

## Error Handling in Adapters

### Protocol Error Translation
```python
class FlextLdapProtocolErrorTranslator:
    """Translates external protocol errors to domain errors."""
    
    def translate_ldap_error(
        self,
        ldap_error: LDAPException
    ) -> FlextResult[None]:
        """Translate LDAP protocol error to domain error."""
        
        error_mapping = {
            'INVALID_DN_SYNTAX': 'Invalid distinguished name format',
            'NO_SUCH_OBJECT': 'LDAP entry not found',
            'ALREADY_EXISTS': 'LDAP entry already exists',
            'INSUFFICIENT_ACCESS_RIGHTS': 'Insufficient permissions'
        }
        
        error_code = ldap_error.result.get('result', 'UNKNOWN')
        domain_error = error_mapping.get(error_code, f'LDAP operation failed: {error_code}')
        
        return FlextResult.fail(domain_error)
```

## Configuration for Adapters

### Adapter Configuration
```python
class FlextLdapAdapterConfig(FlextBaseSettings):
    """Configuration for adapter layer components."""
    
    # Directory adapter settings
    directory_adapter_enabled: bool = True
    directory_timeout: int = 30
    directory_retry_attempts: int = 3
    
    # Singer adapter settings
    singer_adapter_enabled: bool = False
    singer_catalog_cache_ttl: int = 3600
    
    # Format adapter settings
    ldif_encoding: str = 'utf-8'
    json_pretty_print: bool = False
    
    class Config:
        env_prefix = "FLEXT_LDAP_ADAPTER_"
```

## Testing Strategies

### Adapter Unit Testing
```python
@pytest.mark.asyncio
async def test_directory_adapter_search():
    """Test directory adapter search functionality."""
    # Arrange
    mock_connection = MockLdapConnection()
    adapter = FlextLdapDirectoryAdapter(test_config)
    
    # Act
    result = await adapter.search_entries(
        base_dn=FlextLdapDistinguishedName("ou=users,dc=test,dc=com"),
        filter_spec=FlextLdapFilter("(uid=test)"),
        scope=FlextLdapSearchScope.SUBTREE
    )
    
    # Assert
    assert result.is_success
    assert len(result.data) == 1
    assert result.data[0].dn == "uid=test,ou=users,dc=test,dc=com"
```

### Integration Testing
```python
@pytest.mark.integration
async def test_singer_adapter_roundtrip():
    """Test Singer adapter round-trip conversion."""
    # Test conversion from LDAP → Singer → LDAP maintains data integrity
    original_entry = create_test_ldap_entry()
    
    # Convert to Singer format
    singer_record = adapter.convert_to_singer_record(original_entry)
    
    # Convert back to LDAP format
    converted_entry = adapter.convert_from_singer_record(singer_record)
    
    # Verify data integrity
    assert converted_entry.dn == original_entry.dn
    assert converted_entry.attributes == original_entry.attributes
```

The adapters layer ensures clean integration with external systems while maintaining the integrity of domain models and providing proper error handling and data conversion capabilities.
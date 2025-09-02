# FLEXT-LDAP Complete Class-Based Refactoring Plan

## Objective
Transform flext-ldap to use **ONLY** class-based architecture with `FlextLDAP[Module]` naming pattern. Eliminate ALL helper functions, factory functions, and standalone code.

## New Module Architecture

### 1. FlextLDAPApi (api.py)
```python
class FlextLDAPApi:
    """Main API entry point - no factory functions"""
    def __init__(self, config: FlextLDAPSettings | None = None) -> None: ...
    async def connect(...) -> FlextResult[str]: ...
    async def search(...) -> FlextResult[list[FlextLDAPEntry]]: ...
    # All current methods remain, helper methods become private
```

### 2. FlextLDAPContainer (container.py)  
```python
class FlextLDAPContainer:
    """Container management - eliminates all standalone functions"""
    def __init__(self) -> None: ...
    def get_container(self) -> FlextContainer: ...
    def register_services(self) -> FlextResult[None]: ...
    def configure(self, settings: FlextLDAPSettings) -> FlextResult[None]: ...
    def reset(self) -> None: ...
```

### 3. FlextLDAPSettings (settings.py)
```python 
class FlextLDAPSettings(FlextConfig):
    """Settings - eliminate factory functions"""
    # Current class remains
    # Remove: create_development_config(), create_production_config(), create_test_config()
    
    @classmethod
    def create_development(cls) -> "FlextLDAPSettings": ...
    @classmethod  
    def create_production(cls) -> "FlextLDAPSettings": ...
    @classmethod
    def create_test(cls) -> "FlextLDAPSettings": ...
```

### 4. FlextLDAPUtilities (utilities.py - rename from utils.py)
```python
class FlextLDAPUtilities:
    """All utility functions as class methods - no standalone functions"""
    
    class Validation:
        @staticmethod
        def validate_dn(dn: str) -> FlextResult[str]: ...
        @staticmethod  
        def validate_attribute_name(name: str) -> FlextResult[str]: ...
        @staticmethod
        def validate_attribute_value(value: str) -> FlextResult[str]: ...
        @staticmethod
        def sanitize_attribute_name(name: str) -> str: ...
```

### 5. FlextLDAPTypeGuards (type_guards.py)
```python
class FlextLDAPTypeGuards:
    """Type guards as class methods"""
    @staticmethod
    def is_ldap_dn(value: object) -> TypeGuard[str]: ...
    @staticmethod
    def is_ldap_attribute_value(value: object) -> TypeGuard[TLdapAttributeValue]: ...
    # All current functions become static methods
```

### 6. Other modules remain class-based:
- FlextLDAPClient (clients.py) ✓
- FlextLDAPService (services.py) ✓  
- FlextLDAPRepository (repositories.py) ✓
- Domain classes ✓
- Entity classes ✓

## Changes Required

### A. Eliminate Factory Functions
- Remove: `get_ldap_api()`, `create_ldap_api()` → Use `FlextLDAPApi()` directly
- Remove: `get_ldap_container()`, `reset_ldap_container()` → Use `FlextLDAPContainer()` methods
- Remove: `create_development_config()`, etc. → Use `FlextLDAPSettings.create_development()` 

### B. Eliminate Standalone Functions  
- `flext_ldap_validate_dn()` → `FlextLDAPUtilities.Validation.validate_dn()`
- `flext_ldap_validate_attribute_name()` → `FlextLDAPUtilities.Validation.validate_attribute_name()`
- `flext_ldap_validate_attribute_value()` → `FlextLDAPUtilities.Validation.validate_attribute_value()`
- `flext_ldap_sanitize_attribute_name()` → `FlextLDAPUtilities.Validation.sanitize_attribute_name()`
- All type guards in type_guards.py → `FlextLDAPTypeGuards` static methods

### C. Remove Legacy/Compatibility Code
- Completely remove utils.py (legacy facade) 
- Remove all deprecation warnings
- Remove backward compatibility layers
- No fallback modes

### D. Update All References
- src/ modules
- examples/ 
- tests/
- scripts/
- __init__.py exports

## Implementation Order
1. **FlextLDAPContainer** - Core infrastructure
2. **FlextLDAPUtilities** - Replace utils.py completely  
3. **FlextLDAPTypeGuards** - Convert type_guards.py
4. **FlextLDAPSettings** - Convert factory functions to class methods
5. **Update __init__.py** - Remove factory function exports
6. **Update all examples/** - Use new class-based API
7. **Update all tests/** - Achieve ~100% coverage 
8. **Update scripts/** - Use new patterns
9. **Quality gates** - ruff, mypy, pyright all pass

## Success Criteria
- ✅ Zero standalone functions outside of classes
- ✅ All modules follow FlextLDAP[Module] naming  
- ✅ No factory functions
- ✅ No legacy/compatibility code
- ✅ No helpers outside classes
- ✅ 100% test coverage maintained
- ✅ All quality gates pass (ruff, mypy, pyright)
- ✅ No functionality loss

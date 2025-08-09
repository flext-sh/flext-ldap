# FLEXT LIBRARIES MAPPING - MANDATORY USAGE GUIDE

**CREATED**: 2025-08-07 - Comprehensive mapping of flext-* libraries that MUST be used instead of duplicating functionality

## 🎯 MANDATORY FLEXT-* LIBRARY USAGE

### **FOUNDATION LIBRARIES (MUST USE):**

#### **flext-core** - Foundation Patterns (ALWAYS IMPORT BY ROOT)
```python
# ✅ CORRECT - Import by root
from flext_core import (
    FlextResult, FlextRepository, FlextDomainService, FlextEntity, 
    FlextValue, FlextAggregateRoot, FlextContainer, FlextGenerators,
    FlextTypes, get_logger, get_flext_container
)

# ❌ WRONG - Don't import from submodules
from flext_core.semantic_types import FlextTypes  # VIOLATION
from flext_core.utilities import FlextGenerators  # VIOLATION
```

**ELIMINATES flext-ldap duplications:**
- All abstract classes → Use `FlextRepository`, `FlextDomainService` 
- All base entities → Use `FlextEntity`, `FlextValue`, `FlextAggregateRoot`
- All result handling → Use `FlextResult[T]` railway pattern
- All DI containers → Use `FlextContainer`, `get_flext_container()`
- All ID generation → Use `FlextGenerators.generate_id()`
- All logging → Use `get_logger(__name__)`

#### **flext-observability** - Observability & Monitoring (MUST USE)
```python
# ✅ CORRECT
from flext_observability import (
    FlextObservabilityService, FlextSecurityEventLogger, FlextMetricsCollector,
    FlextErrorCorrelator, FlextSchemaDiscovery, FlextAuditTrail
)
```

**ELIMINATES flext-ldap duplications:**
- `infrastructure/security_event_logger.py` → Use `FlextSecurityEventLogger`
- `infrastructure/error_correlation.py` → Use `FlextErrorCorrelator` 
- `infrastructure/schema_discovery.py` → Use `FlextSchemaDiscovery`
- All security logging → Use observability patterns
- All metrics collection → Use observability patterns

#### **flext-ldif** - LDIF Processing (MUST USE)
```python
# ✅ CORRECT
from flext_ldif import (
    FlextLdifAPI, FlextLdifProcessor, FlextLdifValidator,
    FlextLdifExporter, FlextLdifImporter
)
```

**ELIMINATES flext-ldap duplications:**
- All LDIF export functionality in `abstracts.py` → Use `FlextLdifExporter`
- All LDIF import functionality in `abstracts.py` → Use `FlextLdifImporter`
- All LDIF processing → Use `FlextLdifAPI`
- All LDIF validation → Use `FlextLdifValidator`

#### **flext-auth** - Authentication & Authorization (MUST USE)
```python
# ✅ CORRECT
from flext_auth import (
    FlextAuthService, FlextCredentialManager, FlextSessionManager,
    FlextPasswordValidator, FlextTokenManager
)
```

**ELIMINATES flext-ldap duplications:**
- All authentication config in multiple files → Use `FlextAuthService`
- All credential management → Use `FlextCredentialManager`
- All session management → Use `FlextSessionManager`
- All password handling → Use `FlextPasswordValidator`

### **INTEGRATION LIBRARIES (USE WHEN NEEDED):**

#### **flext-api** - REST API Patterns (USE FOR API LAYERS)
```python
# ✅ CORRECT
from flext_api import (
    FlextAPIBuilder, FlextAPIClient, FlextEndpointBuilder,
    FlextResponseHandler, FlextRequestValidator
)
```

#### **flext-cli** - CLI Patterns (USE FOR CLI MODULES)
```python
# ✅ CORRECT  
from flext_cli import (
    FlextCliBuilder, FlextCommandBuilder, FlextCliValidator,
    FlextOutputFormatter, FlextCliHelper
)
```

**ELIMINATES flext-ldap duplications:**
- CLI module complexity → Use `FlextCliBuilder` patterns
- Output formatting → Use `FlextOutputFormatter`
- Command validation → Use `FlextCliValidator`

#### **flext-meltano** - Singer/DBT Patterns (USE FOR DATA INTEGRATION)
```python
# ✅ CORRECT
from flext_meltano import (
    FlextMeltanoService, FlextSingerTap, FlextSingerTarget,
    FlextDBTTransformer, FlextDataValidator
)
```

#### **flext-grpc** - gRPC Communication (USE FOR GRPC)
```python
# ✅ CORRECT
from flext_grpc import (
    FlextGrpcService, FlextGrpcClient, FlextGrpcValidator,
    FlextProtoBuilder, FlextGrpcSecurity
)
```

## 🚫 FORBIDDEN DUPLICATIONS

### **NEVER REIMPLEMENT THESE IN flext-ldap:**

1. **Abstract Classes** → ALWAYS use flext-core base classes
2. **Repository Patterns** → ALWAYS use `FlextRepository`
3. **Domain Services** → ALWAYS use `FlextDomainService`  
4. **Value Objects** → ALWAYS use `FlextValue`
5. **Entities** → ALWAYS use `FlextEntity`
6. **Result Handling** → ALWAYS use `FlextResult[T]`
7. **Logging** → ALWAYS use `get_logger()` from flext-core
8. **Security Events** → ALWAYS use flext-observability
9. **LDIF Processing** → ALWAYS use flext-ldif
10. **Authentication** → ALWAYS use flext-auth
11. **Configuration** → ALWAYS use flext-core patterns
12. **Dependency Injection** → ALWAYS use flext-core container

### **IMPORT VIOLATIONS TO FIX:**

#### **❌ CURRENT VIOLATIONS:**
```python
# WRONG - Submodule imports
from flext_core.semantic_types import FlextTypes
from flext_core.utilities import FlextGenerators  
from flext_ldap.infrastructure.ldap_client import FlextLdapClient

# WRONG - Not using existing flext-* libraries
from flext_ldap.infrastructure.security_event_logger import FlextLdapSecurityEventLogger
```

#### **✅ CORRECTED IMPORTS:**
```python
# CORRECT - Root imports
from flext_core import FlextTypes, FlextGenerators
from flext_ldap import FlextLdapClient

# CORRECT - Using existing flext-* libraries  
from flext_observability import FlextSecurityEventLogger
```

## 📋 REFACTORING PRIORITIES

### **PHASE 1: Foundation Consolidation**
1. Replace all abstract classes with flext-core extensions
2. Centralize all imports to use root imports only
3. Remove all duplicated repository/service patterns

### **PHASE 2: External Library Integration**  
1. Replace security_event_logger with flext-observability
2. Replace LDIF functionality with flext-ldif
3. Replace auth functionality with flext-auth

### **PHASE 3: Module Restructuring**
1. Consolidate everything into protocols.py, models.py, constants.py
2. Move all implementations to properly named PEP8 modules
3. Create facade layers for legacy compatibility

### **PHASE 4: DI Library Transformation**
1. Convert from service implementation to DI library patterns
2. Expose only interfaces, not concrete implementations
3. Use copy→refactor→replace strategy with warnings

## 🎯 SUCCESS CRITERIA

- **0 duplicated abstract classes** - All use flext-core patterns
- **0 duplicated functionality** - All use appropriate flext-* libraries  
- **100% root imports** - Never import from submodules
- **100% flext-* integration** - No reimplemented functionality
- **100% PEP8 compliance** - All modules follow naming conventions
- **100% DI library pattern** - No service implementations exposed
- **100% advanced Python 3.13** - Extensive Pydantic usage
- **Legacy compatibility only** - Via __init__.py and legacy.py facades

---

**AUTHORITY**: This mapping is MANDATORY and must be followed 100%  
**ENFORCEMENT**: All violations will be systematically eliminated  
**COMPLETION**: Only when ALL items above are fully implemented
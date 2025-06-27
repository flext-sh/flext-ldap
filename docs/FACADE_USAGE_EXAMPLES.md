# LDAP Core Shared - Facade Pattern Usage Examples

## 📚 Guia Prático de Uso da Nova API

Este documento fornece exemplos práticos de como usar a nova API refatorada com o padrão Facade, demonstrando que **toda a funcionalidade permanece idêntica** após a refatoração.

## 🚀 Quick Start

### **Basic Import (Unchanged)**

```python
# ✅ MESMA importação de antes - 100% compatível
from ldap_core_shared.api import LDAP, LDAPConfig, connect, ldap_session

# ✅ Imports específicos também funcionam
from ldap_core_shared.api import Result, Query, validate_ldap_config
```

### **Configuration (Unchanged)**

```python
# ✅ MESMA configuração de antes
config = LDAPConfig(
    server="ldap.company.com",
    auth_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=company,dc=com",
    auth_password="secure_password",
    base_dn="dc=company,dc=com"
)

# ✅ Auto-detection continua funcionando
config_tls = LDAPConfig(
    server="ldaps://secure.company.com:636",  # Auto-detects TLS + port
    auth_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=company,dc=com",
    auth_password="secure_password",
    base_dn="dc=company,dc=com"
)
```

## 👥 User Operations Examples

### **Find User by Email (Unchanged)**

```python
async def find_user_example():
    """✅ MESMO código de antes - delegação transparente."""

    config = LDAPConfig(...)

    async with LDAP(config) as ldap:
        # Procura usuário por email
        user_result = await ldap.find_user_by_email("john.doe@company.com")

        if user_result.success:
            user = user_result.data
            print(f"Found: {user.get_attribute('cn')}")
            print(f"Email: {user.get_attribute('mail')}")
            print(f"Department: {user.get_attribute('department')}")
        else:
            print(f"Error: {user_result.error}")
```

### **Find Users in Department (Unchanged)**

```python
async def find_department_users_example():
    """✅ MESMO código de antes - busineses logic delegada."""

    async with LDAP(config) as ldap:
        # Busca todos usuários do departamento
        users_result = await ldap.find_users_in_department("Engineering")

        if users_result.success:
            users = users_result.data
            print(f"Found {len(users)} engineers:")

            for user in users:
                name = user.get_attribute('cn')
                email = user.get_attribute('mail')
                title = user.get_attribute('title')
                print(f"  - {name} ({email}) - {title}")
        else:
            print(f"Error: {users_result.error}")
```

### **Find User by Name with Wildcards (Unchanged)**

```python
async def find_user_wildcard_example():
    """✅ MESMO código de antes - query building delegada."""

    async with LDAP(config) as ldap:
        # Busca usuários com nome começando com "John"
        users_result = await ldap.find_user_by_name("John*")

        if users_result.success and users_result.data:
            user = users_result.data
            print(f"Found: {user.get_attribute('cn')}")
```

## 🔍 Query Builder Examples (Enhanced)

### **Simple Query (Unchanged)**

```python
async def simple_query_example():
    """✅ MESMO código de antes - fluent interface preservada."""

    async with LDAP(config) as ldap:
        # Query simples para todos os usuários
        users = await (ldap.query()
            .users()
            .execute())

        if users.success:
            print(f"Found {len(users.data)} users")
```

### **Complex Fluent Query (Unchanged)**

```python
async def complex_query_example():
    """✅ MESMO código de antes - builder pattern preservado."""

    async with LDAP(config) as ldap:
        # Query complexa com filtros múltiplos
        managers = await (ldap.query()
            .users()
            .in_department("Engineering")
            .with_title("*Manager*")
            .enabled_only()
            .select("cn", "mail", "title", "department")
            .limit(25)
            .sort_by("cn")
            .execute())

        if managers.success:
            print(f"Found {len(managers.data)} engineering managers")
            for manager in managers.data:
                print(f"  - {manager.get_attribute('cn')} ({manager.get_attribute('mail')})")
```

### **Department-Specific Queries (Enhanced)**

```python
async def department_queries_example():
    """✅ Queries orientadas ao domínio - semântica de negócio."""

    async with LDAP(config) as ldap:
        # IT department users
        it_users = await (ldap.query()
            .users()
            .in_department("IT")
            .enabled_only()
            .select_basic()  # Seleciona atributos comuns automaticamente
            .execute())

        # Engineering managers
        eng_managers = await (ldap.query()
            .users()
            .in_department("Engineering")
            .with_title("*Manager*")
            .select("cn", "mail", "title")
            .execute())

        # Sales team with phone numbers
        sales_with_phones = await (ldap.query()
            .users()
            .in_department("Sales")
            .where("(telephoneNumber=*)")  # Custom LDAP filter
            .select("cn", "mail", "telephoneNumber")
            .execute())
```

### **Advanced Query Patterns (New)**

```python
async def advanced_query_patterns():
    """🆕 Novos padrões avançados de query - delegação para Query builder."""

    async with LDAP(config) as ldap:
        # Count users without returning data (performance optimization)
        user_count = await (ldap.query()
            .users()
            .in_department("Engineering")
            .count())

        print(f"Engineering has {user_count.data} users")

        # Get first result only (optimization)
        first_manager = await (ldap.query()
            .users()
            .with_title("*Manager*")
            .select_basic()
            .first())

        if first_manager.success and first_manager.data:
            print(f"First manager: {first_manager.data.get_attribute('cn')}")

        # Custom location queries
        workstation_computers = await (ldap.query()
            .computers()
            .in_location("ou=Workstations,dc=company,dc=com")
            .where("(operatingSystem=Windows*)")
            .select("cn", "operatingSystem", "lastLogon")
            .execute())
```

## 👥 Group Operations Examples

### **Group Management (Unchanged)**

```python
async def group_operations_example():
    """✅ MESMO código de antes - group operations delegadas."""

    async with LDAP(config) as ldap:
        # Find specific group
        group_result = await ldap.find_group_by_name("Domain Admins")

        if group_result.success:
            group = group_result.data
            print(f"Group: {group.get_attribute('cn')}")
            print(f"Description: {group.get_attribute('description')}")

        # Get group members
        members_result = await ldap.get_group_members("Engineering")
        if members_result.success:
            members = members_result.data
            print(f"Engineering has {len(members)} members")

        # Check user membership
        is_member = await ldap.is_user_in_group("john.doe", "Domain Admins")
        if is_member.success:
            print(f"Is john.doe REDACTED_LDAP_BIND_PASSWORD? {is_member.data}")

        # Find empty groups (maintenance)
        empty_groups = await ldap.find_empty_groups()
        if empty_groups.success:
            print(f"Found {len(empty_groups.data)} empty groups")
```

### **Group Queries (Enhanced)**

```python
async def group_query_examples():
    """🆕 Enhanced group queries - delegação para Query builder."""

    async with LDAP(config) as ldap:
        # All groups in organization
        all_groups = await (ldap.query()
            .groups()
            .select("cn", "description", "member")
            .execute())

        # Groups with specific naming pattern
        security_groups = await (ldap.query()
            .groups()
            .with_name("SEC_*")
            .select_basic()
            .execute())

        # Large groups (with many members)
        large_groups = await (ldap.query()
            .groups()
            .where("(member>=*10*)")  # Groups with many members
            .select("cn", "description")
            .sort_by("cn")
            .execute())
```

## 🏢 Enterprise Features Examples

### **Connection Manager Integration (Unchanged)**

```python
async def enterprise_connection_example():
    """✅ MESMO código de antes - ConnectionManager integration preservada."""

    config = LDAPConfig(
        server="ldap://primary.company.com,ldap://secondary.company.com",
        auth_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=company,dc=com",
        auth_password="enterprise_password",
        base_dn="dc=company,dc=com",
        pool_size=20  # Enterprise connection pool
    )

    # Enterprise mode with automatic failover, retry, and pooling
    async with LDAP(config, use_connection_manager=True) as ldap:
        # Connection info includes enterprise details
        connection_info = ldap.get_connection_info()
        print(f"Connection mode: {connection_info['status']['connection_mode']}")

        if 'enterprise' in connection_info:
            enterprise_info = connection_info['enterprise']
            print(f"Healthy servers: {enterprise_info['healthy_servers']}")
            print(f"Total servers: {enterprise_info['total_servers']}")
            print(f"Strategy: {enterprise_info['strategy']}")

        # Operations use enterprise features automatically
        users = await ldap.find_users_in_department("Engineering")
        # ^ Uses connection pooling, retry logic, failover automatically
```

### **Performance Monitoring (New)**

```python
async def performance_monitoring_example():
    """🆕 Performance monitoring - execution time tracking automático."""

    async with LDAP(config) as ldap:
        # All operations return execution time
        start_time = time.time()

        users_result = await ldap.find_users_in_department("Engineering")

        if users_result.success:
            print(f"Query took: {users_result.execution_time_ms}ms")
            print(f"Found: {len(users_result.data)} users")
            print(f"Context: {users_result.context}")

        # Connection testing with diagnostics
        connection_test = await ldap.test_connection()
        if connection_test.success:
            print(f"Connection test: {connection_test.execution_time_ms}ms")
            print(f"Connection healthy: {connection_test.data}")
```

## ✅ Validation Examples

### **Configuration Validation (Enhanced)**

```python
async def configuration_validation_example():
    """🆕 Enhanced configuration validation - delegação para Validation module."""

    config = LDAPConfig(...)

    # Comprehensive configuration validation
    validation_result = await validate_ldap_config(
        config,
        test_connection=True,      # Test actual connectivity
        validate_schema=True       # Validate directory schema
    )

    if validation_result.success:
        validation_data = validation_result.data

        print("✅ Configuration Valid")
        print(f"Connection test: {validation_data['connection_test']['successful']}")

        if validation_data.get('schema_validation', {}).get('performed'):
            schema_info = validation_data['schema_validation']
            print(f"Schema compliance: {schema_info['compliance_rate']:.1%}")

            if schema_info['recommendations']:
                print("Recommendations:")
                for rec in schema_info['recommendations']:
                    print(f"  - {rec}")
    else:
        print(f"❌ Configuration Invalid: {validation_result.error}")
        if validation_result.data:
            issues = validation_result.data.get('config_validation', {}).get('issues', [])
            for issue in issues:
                print(f"  - {issue}")
```

### **Entry Schema Validation (New)**

```python
async def entry_validation_example():
    """🆕 Entry schema validation - business rules validation."""

    async with LDAP(config) as ldap:
        # Find user for validation
        user_result = await ldap.find_user_by_email("john.doe@company.com")

        if user_result.success and user_result.data:
            user = user_result.data

            # Validate entry against schema
            validation = await ldap.validate_entry_schema(
                user,
                strict=False  # Warnings vs errors
            )

            if validation.success:
                validation_data = validation.data

                if validation_data['schema_compliance']:
                    print("✅ Entry is schema compliant")
                else:
                    print("⚠️ Entry has schema issues")

                    for error in validation_data['errors']:
                        print(f"  ❌ Error: {error}")

                    for warning in validation_data['warnings']:
                        print(f"  ⚠️ Warning: {warning}")

                    for rec in validation_data['recommendations']:
                        print(f"  💡 Recommendation: {rec}")
```

### **Directory-Wide Validation (New)**

```python
async def directory_validation_example():
    """🆕 Directory-wide schema validation - data quality metrics."""

    async with LDAP(config) as ldap:
        # Validate entire directory schema compliance
        directory_validation = await ldap.validate_directory_schema()

        if directory_validation.success:
            validation_data = directory_validation.data

            print(f"📊 Directory Validation Results")
            print(f"Entries validated: {validation_data['entries_validated']}")
            print(f"Schema compliant: {validation_data['schema_compliant']}")
            print(f"Compliance rate: {validation_data['compliance_rate']:.1%}")

            # Data quality metrics
            metrics = validation_data.get('data_quality_metrics', {})
            print(f"\n📈 Data Quality Metrics:")
            print(f"Email coverage: {metrics.get('email_coverage', 0):.1f}%")
            print(f"Phone coverage: {metrics.get('phone_coverage', 0):.1f}%")
            print(f"Department coverage: {metrics.get('department_coverage', 0):.1f}%")
            print(f"Complete profiles: {metrics.get('complete_profiles', 0):.1f}%")

            # Object class distribution
            distribution = validation_data.get('object_class_distribution', {})
            print(f"\n📋 Object Class Distribution:")
            for obj_class, count in distribution.items():
                print(f"  {obj_class}: {count}")

            # Recommendations
            recommendations = validation_data.get('recommendations', [])
            if recommendations:
                print(f"\n💡 Recommendations:")
                for rec in recommendations:
                    print(f"  - {rec}")
```

## 🛠️ Factory Functions (Unchanged)

### **Quick Connect (Unchanged)**

```python
async def quick_connect_example():
    """✅ MESMO código de antes - factory functions preservadas."""

    # Quick connection without explicit config object
    ldap = await connect(
        server="ldap.company.com",
        auth_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=company,dc=com",
        auth_password="password",
        base_dn="dc=company,dc=com",
        use_connection_manager=True
    )

    try:
        users = await ldap.find_users_in_department("IT")
        print(f"Found {len(users.data)} IT users")
    finally:
        await ldap._disconnect()
```

### **Session Context Manager (Unchanged)**

```python
async def session_context_example():
    """✅ MESMO código de antes - context manager preservado."""

    # Automatic resource management
    async with ldap_session(
        server="ldap.company.com",
        auth_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=company,dc=com",
        auth_password="password",
        base_dn="dc=company,dc=com"
    ) as ldap:
        # Connection automatically managed

        # Multiple operations in same session
        user = await ldap.find_user_by_email("REDACTED_LDAP_BIND_PASSWORD@company.com")
        groups = await ldap.get_user_groups(user.data) if user.success else None
        stats = await ldap.get_directory_stats()

        print(f"Session completed successfully")

    # Connection automatically closed
```

## 📊 Directory Analytics Examples (Enhanced)

### **Directory Statistics (Enhanced)**

```python
async def directory_analytics_example():
    """🆕 Enhanced directory analytics - comprehensive statistics."""

    async with LDAP(config) as ldap:
        # Get comprehensive directory statistics
        stats_result = await ldap.get_directory_stats()

        if stats_result.success:
            stats = stats_result.data

            print("📊 Directory Statistics:")
            print(f"Total users: {stats['total_users']}")
            print(f"Enabled users: {stats['enabled_users']}")
            print(f"Disabled users: {stats['disabled_users']}")
            print(f"Total groups: {stats['total_groups']}")
            print(f"Empty groups: {stats['empty_groups']}")

            # Calculate derived metrics
            if stats['total_users'] > 0:
                enabled_percentage = (stats['enabled_users'] / stats['total_users']) * 100
                print(f"Enabled percentage: {enabled_percentage:.1f}%")

            # Group utilization
            if stats['total_groups'] > 0:
                utilized_groups = stats['total_groups'] - stats['empty_groups']
                utilization = (utilized_groups / stats['total_groups']) * 100
                print(f"Group utilization: {utilization:.1f}%")
```

### **Advanced Analytics Queries (New)**

```python
async def advanced_analytics_example():
    """🆕 Advanced analytics - business intelligence queries."""

    async with LDAP(config) as ldap:
        # Department distribution analysis
        departments = {}

        # Get all users with department info
        users_with_dept = await (ldap.query()
            .users()
            .where("(department=*)")
            .select("cn", "department", "title")
            .execute())

        if users_with_dept.success:
            for user in users_with_dept.data:
                dept = user.get_attribute('department')
                if dept:
                    departments[dept] = departments.get(dept, 0) + 1

            print("📈 Department Distribution:")
            for dept, count in sorted(departments.items(), key=lambda x: x[1], reverse=True):
                print(f"  {dept}: {count} users")

        # Title analysis
        titles = {}
        for user in users_with_dept.data:
            title = user.get_attribute('title')
            if title and 'manager' in title.lower():
                titles[title] = titles.get(title, 0) + 1

        print("\n👔 Management Titles:")
        for title, count in sorted(titles.items(), key=lambda x: x[1], reverse=True):
            print(f"  {title}: {count}")
```

## 🔧 Error Handling Patterns

### **Result Pattern Usage (Enhanced)**

```python
async def error_handling_example():
    """🆕 Enhanced error handling - Result[T] pattern examples."""

    async with LDAP(config) as ldap:
        # Success case
        user_result = await ldap.find_user_by_email("existing@company.com")

        if user_result.success:
            user = user_result.data
            print(f"✅ Found user: {user.get_attribute('cn')}")
            print(f"   Execution time: {user_result.execution_time_ms}ms")

            # Access context data
            if user_result.context:
                print(f"   Context: {user_result.context}")

        # Error case
        missing_user = await ldap.find_user_by_email("nonexistent@company.com")

        if not missing_user.success:
            print(f"❌ Error: {missing_user.error}")
            print(f"   Error code: {missing_user.error_code}")
            print(f"   Execution time: {missing_user.execution_time_ms}ms")

            # Default data available even on error
            if hasattr(missing_user, 'data'):
                print(f"   Default data: {missing_user.data}")

        # Exception handling
        try:
            # Operations can still raise exceptions for critical errors
            malformed_result = await ldap.find_user_by_email("invalid-email-format")
        except Exception as e:
            print(f"💥 Exception: {e}")
```

### **Chainable Error Handling (New)**

```python
async def chainable_error_handling():
    """🆕 Chainable error handling - clean error management."""

    async with LDAP(config) as ldap:
        # Chain operations with error checking
        user_result = await ldap.find_user_by_email("john.doe@company.com")

        if user_result.success:
            # Chain dependent operations
            groups_result = await ldap.get_user_groups(user_result.data)

            if groups_result.success:
                groups = groups_result.data
                print(f"User {user_result.data.get_attribute('cn')} is in {len(groups)} groups")

                for group in groups:
                    group_name = group.get_attribute('cn')
                    print(f"  - {group_name}")
            else:
                print(f"Failed to get groups: {groups_result.error}")
        else:
            print(f"User not found: {user_result.error}")
```

## 🏆 Migration Guide

### **Before Refactoring vs After**

```python
# ❌ ANTES (código antigo - ainda funciona!)
from ldap_core_shared.api import LDAP, LDAPConfig

async def old_code_example():
    """Este código CONTINUA funcionando identicamente."""
    config = LDAPConfig(...)

    async with LDAP(config) as ldap:
        users = await ldap.find_users_in_department("Engineering")
        # ^ Internamente: agora delega para LDAPOperations module

# ✅ DEPOIS (mesmo código - com benefícios internos!)
from ldap_core_shared.api import LDAP, LDAPConfig

async def new_code_example():
    """MESMO código - mas agora com True Facade Pattern internamente."""
    config = LDAPConfig(...)

    async with LDAP(config) as ldap:
        users = await ldap.find_users_in_department("Engineering")
        # ^ Internamente: True Facade → LDAPOperations → Query Builder → ConnectionManager
```

### **New Capabilities (Optional Enhancements)**

```python
async def enhanced_capabilities_example():
    """🆕 Novas capacidades disponíveis (opcionais)."""

    async with LDAP(config) as ldap:
        # Enhanced query capabilities
        complex_query = await (ldap.query()
            .users()
            .in_department("Engineering")
            .with_title("*Senior*")
            .enabled_only()
            .member_of("VPN_Users")
            .select_basic()
            .limit(50)
            .sort_by("cn")
            .execute())

        # Enhanced validation
        directory_health = await ldap.validate_directory_schema()

        # Performance monitoring
        print(f"Query executed in: {complex_query.execution_time_ms}ms")

        # Connection diagnostics
        connection_info = ldap.get_connection_info()
        print(f"Connection mode: {connection_info['status']['connection_mode']}")
```

## 🎯 Best Practices

### **1. Use Context Managers**

```python
# ✅ SEMPRE use context manager para resource management
async with LDAP(config) as ldap:
    # Operations here
    pass
# Connection automatically closed
```

### **2. Handle Results Properly**

```python
# ✅ SEMPRE verifique success antes de usar data
result = await ldap.find_user_by_email("user@company.com")
if result.success:
    user = result.data  # Safe to use
    # Process user
else:
    logger.error(f"Failed to find user: {result.error}")
```

### **3. Use Semantic Query Methods**

```python
# ✅ PREFIRA métodos semânticos
users = await (ldap.query()
    .users()
    .in_department("IT")
    .enabled_only())

# ❌ EVITE filtros raw desnecessários
users = await (ldap.query()
    .where("(&(objectClass=person)(department=IT)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"))
```

### **4. Leverage Performance Features**

```python
# ✅ USE count() para contagem sem dados
count = await ldap.query().users().in_department("Engineering").count()

# ✅ USE first() para single results
manager = await ldap.query().users().with_title("*Manager*").first()

# ✅ USE select() para reduzir dados transferidos
users = await (ldap.query()
    .users()
    .select("cn", "mail")  # Only needed attributes
    .execute())
```

## 📋 Summary

### **✅ 100% Backward Compatibility**

- Todo código existente continua funcionando sem modificação
- Mesmas importações, mesma API, mesmo comportamento
- Zero breaking changes

### **🏗️ Enhanced Architecture**

- True Facade Pattern com delegação pura
- 6 módulos especializados com responsabilidade única
- Melhor testabilidade, manutenibilidade e extensibilidade

### **🚀 New Capabilities**

- Enhanced query builder com métodos semânticos
- Comprehensive validation com business rules
- Performance monitoring automático
- Directory analytics e data quality metrics

### **🎯 Developer Experience**

- Código mais legível e auto-documentado
- Melhor IDE support com type hints
- Debugging mais fácil com módulos isolados
- Testes mais rápidos e confiáveis

---

**O resultado é uma API moderna, mantendo 100% de compatibilidade com arquitetura enterprise-grade para o futuro.**

_Documentação criada em: 2025-06-26_  
_Refatoração: God Object → True Facade Pattern_  
_Status: 100% compatível + enhanced capabilities_

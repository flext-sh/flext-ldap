# LDAP Core Shared - API Standardization Migration Guide

## 🎯 **Overview**

This guide helps you migrate from the current LDAP Core Shared API to the new standardized API that provides maximum functionality with minimum complexity. The migration is **100% backward compatible** - your existing code will continue to work without changes.

## 🚀 **Why Migrate?**

### **Current API Challenges:**

- ❌ Inconsistent parameter naming across modules
- ❌ Mixed return types (some wrapped, some direct)
- ❌ Multiple configuration patterns
- ❌ Limited error context information
- ❌ No structured query building

### **Standardized API Benefits:**

- ✅ **Consistent Interfaces** - All operations follow identical patterns
- ✅ **Structured Results** - Rich error information and execution metrics
- ✅ **Fluent Queries** - Chainable query building for complex searches
- ✅ **Semantic Operations** - Domain-specific helper methods
- ✅ **Enhanced Type Safety** - Complete type coverage with validation
- ✅ **Better Performance** - Built-in optimization and monitoring

## 📋 **Migration Strategy**

### **Phase 1: No Changes Required (Immediate)**

Your existing code continues to work unchanged. The library provides full backward compatibility.

### **Phase 2: Gradual Adoption (Recommended)**

Start using new APIs for new code while keeping existing code unchanged.

### **Phase 3: Full Migration (Optional)**

Migrate existing code to new APIs when convenient, following deprecation guidance.

## 🔄 **Migration Examples**

### **1. Basic Connection and Search**

#### **Before (Current API):**

```python
from ldap_core_shared import LDAP

# Current approach
ldap = LDAP.connect_to("server.com", "REDACTED_LDAP_BIND_PASSWORD", "secret")
users = await ldap.find_users(in_location="ou=people")

if users:
    for user in users:
        print(f"User: {user.get_attribute('cn')}")
else:
    print("No users found or error occurred")
```

#### **After (Standardized API):**

```python
from ldap_core_shared.standardized_api import LDAPConfiguration, StandardizedLDAPSession

# New standardized approach
config = (LDAPConfiguration.builder()
    .for_server("ldap://server.com")
    .with_authentication("cn=REDACTED_LDAP_BIND_PASSWORD,dc=company,dc=com", "secret")
    .with_search_base("dc=company,dc=com")
    .build())

async with StandardizedLDAPSession.create(config) as session:
    result = await session.find_users_by_department("IT")

    if result.success:
        print(f"Found {len(result.data)} users in {result.execution_time_ms:.1f}ms")
        for user in result.data:
            print(f"User: {user.get_attribute('cn')}")
    else:
        print(f"Error: {result.error_message}")
        print(f"Error code: {result.error_code}")
```

#### **Key Improvements:**

- ✅ **Structured configuration** with fluent builder
- ✅ **Rich result information** with success/failure and timing
- ✅ **Detailed error context** with error codes and messages
- ✅ **Automatic resource management** with context manager

---

### **2. Complex Search Operations**

#### **Before (Current API):**

```python
# Current approach - manual filter building
filter_expr = "(&(objectClass=person)(department=Engineering)(title=*Manager*))"
users = await ldap.search_for(
    "users",
    in_location="ou=people",
    matching=filter_expr,
    limit=50
)

# No easy way to handle search errors
if not users:
    print("Search failed or no results")
```

#### **After (Standardized API):**

```python
# New fluent query approach
result = await (session.query()
    .in_location("ou=people,dc=company,dc=com")
    .where("(objectClass=person)")
    .and_where("(department=Engineering)")
    .and_where("(title=*Manager*)")
    .select("cn", "mail", "title", "department")
    .limit(50)
    .sort_by("cn")
    .execute())

if result.success:
    print(f"Found {len(result.data)} engineering managers")
    for user in result.data:
        title = user.get_attribute("title")
        print(f"{user.get_attribute('cn')} - {title}")
else:
    print(f"Search failed: {result.error_message}")
    # Rich error context available
    print(f"Context: {result.context}")
```

#### **Key Improvements:**

- ✅ **Chainable query building** - no manual filter construction
- ✅ **Attribute selection** - only retrieve needed data
- ✅ **Result sorting** - built-in sorting capabilities
- ✅ **Structured error handling** - detailed failure information

---

### **3. User and Group Operations**

#### **Before (Current API):**

```python
# Current approach - multiple separate operations
user = await ldap.find_user_by_name("john.doe")
if user:
    groups = await ldap.find_groups_for_user("john.doe")
    print(f"User {user.dn} is in {len(groups)} groups")
else:
    print("User not found")
```

#### **After (Standardized API):**

```python
# New semantic operations approach
user_result = await session.find_user_by_email("john.doe@company.com")

if user_result.success and user_result.data:
    user = user_result.data
    print(f"Found user: {user.get_attribute('cn')}")

    # Get user's groups with structured result
    groups_result = await session.get_user_groups(user.get_attribute("cn"))

    if groups_result.success:
        print(f"User is in {len(groups_result.data)} groups:")
        for group in groups_result.data:
            print(f"  • {group.get_attribute('cn')}")
    else:
        print(f"Failed to get groups: {groups_result.error_message}")
else:
    print("User not found")
```

#### **Key Improvements:**

- ✅ **Semantic operations** - domain-specific methods
- ✅ **Consistent result structure** - all operations return same format
- ✅ **Better error handling** - specific error messages and codes

---

### **4. Configuration Management**

#### **Before (Current API):**

```python
# Current approach - multiple configuration classes
from ldap_core_shared.api import ServerConfig, AuthConfig

server_config = ServerConfig(
    host="ldap.company.com",
    port=636,
    use_ssl=True,
    verify_certificates=True
)

auth_config = AuthConfig(
    username="REDACTED_LDAP_BIND_PASSWORD",
    password="secret",
    domain="company.com"
)

ldap = LDAP(server_config, auth_config)
```

#### **After (Standardized API):**

```python
# New unified configuration approach
config = (LDAPConfiguration.builder()
    .for_server("ldaps://ldap.company.com:636")
    .with_authentication("cn=REDACTED_LDAP_BIND_PASSWORD,dc=company,dc=com", "secret")
    .with_search_base("dc=company,dc=com")
    .with_encryption(enabled=True, verify_certs=True)
    .with_timeout(30)
    .with_pooling(pool_size=10, max_pool_size=50)
    .with_performance_monitoring(enabled=True)
    .build())

session = StandardizedLDAPSession.create(config)
```

#### **Key Improvements:**

- ✅ **Single configuration interface** - no multiple config classes
- ✅ **Fluent builder pattern** - intuitive configuration building
- ✅ **Built-in validation** - immediate feedback on configuration errors
- ✅ **Performance tuning** - connection pooling and monitoring options

---

### **5. Error Handling**

#### **Before (Current API):**

```python
# Current approach - basic exception handling
try:
    users = await ldap.find_users()
    print(f"Found {len(users)} users")
except ConnectionError as e:
    print(f"Connection failed: {e}")
except LDAPError as e:
    print(f"LDAP error: {e}")
except Exception as e:
    print(f"Unknown error: {e}")
```

#### **After (Standardized API):**

```python
# New structured error handling
result = await session.find_users_by_department("Engineering")

if result.success:
    print(f"Found {len(result.data)} users in {result.execution_time_ms:.1f}ms")
    for user in result.data:
        print(f"  {user.get_attribute('cn')}")
else:
    print(f"Operation failed: {result.error_message}")
    print(f"Error code: {result.error_code}")
    print(f"Execution time: {result.execution_time_ms:.1f}ms")

    # Rich context information
    if result.context:
        print(f"Context: {result.context}")

    # Recovery suggestions (if available)
    if "recovery_suggestions" in result.metadata:
        print("Suggestions:")
        for suggestion in result.metadata["recovery_suggestions"]:
            print(f"  • {suggestion}")
```

#### **Key Improvements:**

- ✅ **No exceptions for normal operations** - structured results instead
- ✅ **Rich error context** - detailed information about failures
- ✅ **Performance metrics** - execution timing for all operations
- ✅ **Recovery guidance** - suggestions for resolving issues

---

## 📚 **Advanced Migration Patterns**

### **1. Batch Operations**

#### **Before:**

```python
departments = ["IT", "HR", "Engineering"]
all_users = []

for dept in departments:
    users = await ldap.find_users(with_filter=f"(department={dept})")
    all_users.extend(users)

print(f"Total users: {len(all_users)}")
```

#### **After:**

```python
departments = ["IT", "HR", "Engineering"]

# Concurrent batch processing
tasks = [
    session.find_users_by_department(dept)
    for dept in departments
]

results = await asyncio.gather(*tasks)

total_users = 0
for dept, result in zip(departments, results):
    if result.success:
        count = len(result.data)
        total_users += count
        print(f"{dept}: {count} users ({result.execution_time_ms:.1f}ms)")
    else:
        print(f"{dept}: Error - {result.error_message}")

print(f"Total users: {total_users}")
```

### **2. Complex Query Building**

#### **Before:**

```python
# Manual filter construction
base_filter = "(objectClass=person)"
dept_filter = "(department=Engineering)"
title_filter = "(|(title=*Senior*)(title=*Lead*)(title=*Manager*))"
enabled_filter = "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"

complex_filter = f"(&{base_filter}{dept_filter}{title_filter}{enabled_filter})"

users = await ldap.search_for(
    "users",
    matching=complex_filter,
    with_attributes=["cn", "mail", "title", "department"]
)
```

#### **After:**

```python
# Fluent query building
result = await (session.query()
    .where("(objectClass=person)")
    .and_where("(department=Engineering)")
    .and_where("(|(title=*Senior*)(title=*Lead*)(title=*Manager*))")
    .and_where("(!(userAccountControl:1.2.840.113556.1.4.803:=2))")
    .select("cn", "mail", "title", "department")
    .limit(100)
    .execute())
```

### **3. Directory Analysis**

#### **Before:**

```python
# Manual statistics gathering
users = await ldap.find_users()
groups = await ldap.find_groups()

# Count empty groups manually
empty_groups = []
for group in groups:
    members = group.get_attribute("member")
    if not members:
        empty_groups.append(group)

print(f"Users: {len(users)}")
print(f"Groups: {len(groups)}")
print(f"Empty groups: {len(empty_groups)}")
```

#### **After:**

```python
# Built-in directory statistics
stats_result = await session.get_directory_statistics()

if stats_result.success:
    stats = stats_result.data
    print(f"Directory Statistics (collected in {stats_result.execution_time_ms:.1f}ms):")
    print(f"  Users: {stats['total_users']}")
    print(f"  Groups: {stats['total_groups']}")
    print(f"  Empty groups: {stats['empty_groups']}")
else:
    print(f"Failed to get statistics: {stats_result.error_message}")
```

## 🔄 **Gradual Migration Strategy**

### **Step 1: Install and Test (No Code Changes)**

```bash
# Update to latest version
pip install --upgrade ldap-core-shared

# Test existing code - should work unchanged
python your_existing_script.py
```

### **Step 2: Try New APIs in New Code**

```python
# Use new APIs for new functionality
from ldap_core_shared.standardized_api import LDAPConfiguration, StandardizedLDAPSession

# Keep existing code unchanged
from ldap_core_shared import LDAP  # Still works

# New code uses standardized API
config = LDAPConfiguration.builder()...
session = StandardizedLDAPSession.create(config)

# Existing code continues to work
ldap = LDAP.connect_to(...)
```

### **Step 3: Migrate High-Value Code**

Prioritize migrating code that would benefit most:

1. **Complex searches** → Fluent query interface
2. **Error-prone operations** → Structured error handling
3. **Performance-critical code** → Built-in optimization
4. **Frequently modified code** → Better maintainability

### **Step 4: Complete Migration (Optional)**

When you're ready, migrate remaining code following deprecation warnings.

## 🛠️ **Migration Tools and Helpers**

### **Compatibility Adapter (Temporary)**

For gradual migration, you can use the compatibility adapter:

```python
from ldap_core_shared.standardized_api import StandardizedLDAPSession, LegacyAPIAdapter

# Create standardized session
session = StandardizedLDAPSession.create(config)

# Use adapter for legacy-style calls
legacy = LegacyAPIAdapter(session)

# This provides old-style interface with new backend
users = await legacy.find_users(in_location="ou=people", limit=50)
```

### **Migration Validation Script**

```python
"""Validate migration by comparing old and new API results."""

async def validate_migration():
    # Old API
    old_ldap = LDAP.connect_to("server.com", "REDACTED_LDAP_BIND_PASSWORD", "secret")
    old_users = await old_ldap.find_users()

    # New API
    config = LDAPConfiguration.builder()...
    async with StandardizedLDAPSession.create(config) as session:
        new_result = await session.query().where("(objectClass=person)").execute()
        new_users = new_result.data if new_result.success else []

    # Compare results
    assert len(old_users) == len(new_users), "User count mismatch"
    print("✅ Migration validation passed")
```

## 📊 **Migration Checklist**

### **Before Migration:**

- [ ] Update to latest ldap-core-shared version
- [ ] Test existing code works unchanged
- [ ] Review new API documentation
- [ ] Identify high-value migration candidates

### **During Migration:**

- [ ] Start with new code using standardized APIs
- [ ] Migrate complex searches to fluent queries
- [ ] Update error handling to use structured results
- [ ] Test both old and new APIs side-by-side

### **After Migration:**

- [ ] Remove deprecated API usage
- [ ] Update documentation and examples
- [ ] Train team on new API patterns
- [ ] Monitor performance improvements

## 🎯 **Best Practices for New API**

### **1. Always Use Context Managers**

```python
# ✅ Good
async with StandardizedLDAPSession.create(config) as session:
    result = await session.find_users_by_department("IT")

# ❌ Avoid - manual resource management
session = StandardizedLDAPSession.create(config)
result = await session.find_users_by_department("IT")
# Forgot to close session
```

### **2. Check Success Before Using Data**

```python
# ✅ Good
result = await session.find_user_by_email("user@company.com")
if result.success and result.data:
    user = result.data
    print(f"Found: {user.get_attribute('cn')}")
else:
    print(f"Error: {result.error_message}")

# ❌ Avoid - assuming success
result = await session.find_user_by_email("user@company.com")
user = result.data  # Could be None if error occurred
```

### **3. Use Fluent Queries for Complex Searches**

```python
# ✅ Good - readable and maintainable
result = await (session.query()
    .in_location("ou=users,dc=company,dc=com")
    .where("(objectClass=person)")
    .and_where("(department=Engineering)")
    .and_where("(enabled=true)")
    .select("cn", "mail", "title")
    .limit(50)
    .execute())

# ❌ Avoid - manual filter construction
filter_expr = "(&(objectClass=person)(department=Engineering)(enabled=true))"
# Complex and error-prone
```

### **4. Leverage Semantic Operations**

```python
# ✅ Good - use domain-specific methods
users = await session.find_users_by_department("IT")
is_REDACTED_LDAP_BIND_PASSWORD = await session.is_user_in_group("john.doe", "Admins")
stats = await session.get_directory_statistics()

# ❌ Avoid - reinventing the wheel
# Building complex queries for common operations
```

## 🚀 **Conclusion**

The standardized LDAP API provides a significant improvement in usability, maintainability, and functionality while maintaining 100% backward compatibility. Migration is optional and can be done gradually, allowing you to benefit from the new features immediately while preserving existing investments.

**Key Benefits of Migration:**

- 🎯 **Simpler, more intuitive APIs**
- 📊 **Better error handling and debugging**
- ⚡ **Enhanced performance and monitoring**
- 🔧 **Easier maintenance and testing**
- 🛡️ **Improved type safety and validation**

**Start Today:**

1. Install the latest version
2. Try the new APIs in new code
3. Gradually migrate existing code when convenient
4. Enjoy the improved developer experience!

For questions or assistance with migration, please refer to the API documentation or create an issue in the project repository.

# 🎯 Usage Examples and Tutorials

**Practical Guide to Enterprise LDAP Operations with ldap-core-shared**

This comprehensive guide provides real-world examples, tutorials, and best practices for using the ldap-core-shared library in enterprise environments. From basic operations to advanced workflows, this guide will help you master LDAP development.

## 📋 Table of Contents

### 🚀 Getting Started

- [🎯 Quick Start Guide](#-quick-start-guide)
- [⚙️ Basic Configuration](#-basic-configuration)
- [🔗 Your First Connection](#-your-first-connection)

### 📖 Core Operations

- [🔍 Search Operations](#-search-operations)
- [➕ Creating Entries](#-creating-entries)
- [✏️ Updating Entries](#-updating-entries)
- [🗑️ Deleting Entries](#-deleting-entries)

### 🏢 Enterprise Scenarios

- [👥 User Management](#-user-management)
- [👨‍👩‍👧‍👦 Group Management](#-group-management)
- [🏢 Organization Management](#-organization-management)
- [🔐 Authentication Integration](#-authentication-integration)

### 📄 LDIF Operations

- [📝 LDIF Import/Export](#-ldif-importexport)
- [🔄 LDIF Transformation](#-ldif-transformation)
- [✅ LDIF Validation](#-ldif-validation)
- [🔗 LDIF Merging](#-ldif-merging)

### 🗂️ Schema Management

- [🔍 Schema Discovery](#-schema-discovery)
- [📊 Schema Analysis](#-schema-analysis)
- [🔄 Schema Migration](#-schema-migration)
- [✅ Schema Validation](#-schema-validation)

### ⚡ Advanced Topics

- [📈 Performance Optimization](#-performance-optimization)
- [🔒 Security Best Practices](#-security-best-practices)
- [📊 Monitoring and Metrics](#-monitoring-and-metrics)
- [🔄 Error Handling](#-error-handling)

## 🎯 Quick Start Guide

### Installation and Setup

```bash
# Install the library
pip install ldap-core-shared

# Or for development
git clone https://github.com/your-org/ldap-core-shared.git
cd ldap-core-shared
pip install -e .
```

### Your First LDAP Operation

```python
from ldap_core_shared.core import LDAPConnectionManager, LDAPOperations
from ldap_core_shared.core.connection_manager import ConnectionInfo

# Create connection configuration
conn_info = ConnectionInfo(
    host="ldap.example.com",
    port=389,
    bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
    password="REDACTED_LDAP_BIND_PASSWORD_password"
)

# Initialize components
manager = LDAPConnectionManager(conn_info)
operations = LDAPOperations(manager)

# Connect and perform a simple search
result = manager.connect()
if result.connected:
    print("✅ Connected to LDAP server")

    # Search for all users
    search_result = operations.search_entries(
        base_dn="ou=people,dc=example,dc=com",
        search_filter="(objectClass=person)"
    )

    print(f"Found {search_result.entries_found} users")
    for entry in search_result.entries[:5]:  # Show first 5
        print(f"  {entry.get('cn', [''])[0]} - {entry.get('mail', [''])[0]}")

    manager.disconnect()
else:
    print(f"❌ Connection failed: {result.connection_error}")
```

## ⚙️ Basic Configuration

### Environment-Based Configuration

```python
import os
from ldap_core_shared.core.connection_manager import ConnectionInfo
from ldap_core_shared.utils.constants import DEFAULT_PROFILES

def create_connection_from_env() -> ConnectionInfo:
    """Create connection from environment variables."""

    # Get environment profile
    env = os.getenv("ENVIRONMENT", "DEVELOPMENT")
    profile = DEFAULT_PROFILES[env]

    return ConnectionInfo(
        host=os.getenv("LDAP_HOST", "localhost"),
        port=int(os.getenv("LDAP_PORT", "389")),
        bind_dn=os.getenv("LDAP_BIND_DN"),
        password=os.getenv("LDAP_PASSWORD"),
        use_ssl=os.getenv("LDAP_USE_SSL", "false").lower() == "true",
        timeout=profile["timeout"],
        pool_size=profile["pool_size"],
        max_pool_size=profile["max_pool_size"],
        max_retries=profile["retry_attempts"]
    )

# Usage
conn_info = create_connection_from_env()
```

### Configuration File

```python
import json
from pathlib import Path

def load_config_file(config_path: str) -> ConnectionInfo:
    """Load configuration from JSON file."""

    config_file = Path(config_path)
    if not config_file.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with config_file.open() as f:
        config_data = json.load(f)

    return ConnectionInfo.from_dict(config_data["ldap"])

# Example config.json
config_example = {
    "ldap": {
        "host": "ldap.example.com",
        "port": 636,
        "use_ssl": True,
        "bind_dn": "cn=service-account,ou=services,dc=example,dc=com",
        "timeout": 30,
        "pool_size": 20,
        "max_pool_size": 100
    }
}
```

## 🔗 Your First Connection

### Basic Connection

```python
from ldap_core_shared.core import LDAPConnectionManager
from ldap_core_shared.core.connection_manager import ConnectionInfo

def basic_connection_example():
    """Basic connection example with error handling."""

    conn_info = ConnectionInfo(
        host="ldap.example.com",
        port=389,
        bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        password="password"
    )

    manager = LDAPConnectionManager(conn_info)

    try:
        # Attempt connection
        result = manager.connect()

        if result.connected:
            print("✅ Connection successful!")
            print(f"   Server: {result.host}:{result.port}")
            print(f"   Auth method: {result.auth_method}")
            print(f"   Encryption: {result.encryption}")
            print(f"   Connection time: {result.connection_time:.2f}ms")

            # Perform health check
            health = manager.health_check()
            print(f"   Health check: {'✅ Healthy' if health.connected else '❌ Unhealthy'}")

        else:
            print("❌ Connection failed!")
            if result.connection_error:
                print(f"   Connection error: {result.connection_error}")
            if result.auth_error:
                print(f"   Authentication error: {result.auth_error}")

    except Exception as e:
        print(f"❌ Unexpected error: {e}")

    finally:
        # Always cleanup
        if manager.is_connected():
            manager.disconnect()
            print("🔌 Disconnected from LDAP server")

# Run example
basic_connection_example()
```

### Secure Connection (SSL/TLS)

```python
def secure_connection_example():
    """Example of secure LDAP connection."""

    # SSL connection
    ssl_conn_info = ConnectionInfo(
        host="ldaps.example.com",
        port=636,
        use_ssl=True,
        bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        password="password",
        validate_cert=True,
        ca_cert_path="/etc/ssl/certs/ldap-ca.crt"
    )

    # StartTLS connection
    tls_conn_info = ConnectionInfo(
        host="ldap.example.com",
        port=389,
        use_tls=True,
        bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        password="password"
    )

    for name, conn_info in [("SSL", ssl_conn_info), ("StartTLS", tls_conn_info)]:
        manager = LDAPConnectionManager(conn_info)

        try:
            result = manager.connect()
            if result.connected and result.is_secure:
                print(f"✅ {name} connection established securely")
            else:
                print(f"❌ {name} connection failed or insecure")

        except Exception as e:
            print(f"❌ {name} connection error: {e}")

        finally:
            if manager.is_connected():
                manager.disconnect()
```

## 🔍 Search Operations

### Basic Search

```python
from ldap_core_shared.core import LDAPOperations
from ldap_core_shared.utils.constants import SEARCH_FILTERS, STANDARD_ATTRIBUTES

def basic_search_examples():
    """Basic search operation examples."""

    # Initialize operations
    operations = LDAPOperations(manager)

    # Search all persons
    result = operations.search_entries(
        base_dn="ou=people,dc=example,dc=com",
        search_filter=SEARCH_FILTERS["PERSONS"],  # "(objectClass=person)"
        attributes=[
            STANDARD_ATTRIBUTES["CN"],        # "cn"
            STANDARD_ATTRIBUTES["MAIL"],      # "mail"
            STANDARD_ATTRIBUTES["SN"]         # "sn"
        ]
    )

    if result.success:
        print(f"Found {result.entries_found} persons")
        print(f"Search took {result.search_duration:.2f}ms")
        print(f"Performance: {result.entries_per_second:.0f} entries/second")

        # Process results
        for entry in result.entries:
            dn = entry.get('dn')
            cn = entry.get('cn', [''])[0]
            mail = entry.get('mail', ['No email'])[0]
            print(f"  {cn} ({mail}) - {dn}")
    else:
        print("Search failed:")
        for error in result.errors:
            print(f"  - {error}")

basic_search_examples()
```

### Advanced Search with Filtering

```python
def advanced_search_examples():
    """Advanced search examples with complex filters."""

    operations = LDAPOperations(manager)

    # Example 1: Complex filter
    complex_filter = (
        "(&"                                    # AND condition
        "(objectClass=inetOrgPerson)"          # Must be inetOrgPerson
        "(mail=*)"                             # Must have email
        "(|"                                   # OR condition
        "(departmentNumber=IT)"                # IT department
        "(departmentNumber=Engineering)"       # OR Engineering
        ")"
        "(!(accountStatus=disabled))"          # NOT disabled
        ")"
    )

    result = operations.search_entries(
        base_dn="ou=people,dc=example,dc=com",
        search_filter=complex_filter,
        attributes=["cn", "mail", "departmentNumber", "title"]
    )

    print(f"Active IT/Engineering users: {result.entries_found}")

    # Example 2: Wildcard search
    wildcard_result = operations.search_entries(
        base_dn="ou=people,dc=example,dc=com",
        search_filter="(cn=John*)",  # Names starting with "John"
        attributes=["cn", "mail"]
    )

    print(f"Users named John*: {wildcard_result.entries_found}")

    # Example 3: Date-based search (if supported)
    from datetime import datetime, timedelta

    # Users created in last 30 days
    cutoff_date = datetime.now() - timedelta(days=30)
    date_str = cutoff_date.strftime("%Y%m%d%H%M%SZ")

    recent_users = operations.search_entries(
        base_dn="ou=people,dc=example,dc=com",
        search_filter=f"(createTimestamp>={date_str})",
        attributes=["cn", "createTimestamp"]
    )

    print(f"Recent users (30 days): {recent_users.entries_found}")

advanced_search_examples()
```

### Paginated Search

```python
def paginated_search_example():
    """Example of paginated search for large result sets."""

    operations = LDAPOperations(manager)

    page_size = 100
    all_entries = []

    # Initial search with pagination
    result = operations.search_entries(
        base_dn="ou=people,dc=example,dc=com",
        search_filter="(objectClass=person)",
        attributes=["cn", "mail"],
        page_size=page_size
    )

    all_entries.extend(result.entries)
    print(f"Page 1: {len(result.entries)} entries")

    page_number = 1

    # Continue fetching pages
    while result.has_more_pages:
        page_number += 1

        result = operations.search_entries(
            base_dn="ou=people,dc=example,dc=com",
            search_filter="(objectClass=person)",
            attributes=["cn", "mail"],
            page_size=page_size,
            page_cookie=result.page_cookie
        )

        all_entries.extend(result.entries)
        print(f"Page {page_number}: {len(result.entries)} entries")

        # Safety check to prevent infinite loops
        if page_number > 100:  # Max 100 pages
            print("⚠️  Reached maximum page limit")
            break

    print(f"Total entries retrieved: {len(all_entries)}")
    return all_entries

# Usage
all_users = paginated_search_example()
```

## ➕ Creating Entries

### Basic Entry Creation

```python
from ldap_core_shared.utils.constants import COMMON_OBJECT_CLASSES, STANDARD_ATTRIBUTES

def create_user_example():
    """Example of creating a new user entry."""

    operations = LDAPOperations(manager)

    # Define user attributes
    user_attributes = {
        STANDARD_ATTRIBUTES["OBJECT_CLASS"]: [
            COMMON_OBJECT_CLASSES["PERSON"],        # "person"
            COMMON_OBJECT_CLASSES["INET_ORG_PERSON"] # "inetOrgPerson"
        ],
        STANDARD_ATTRIBUTES["CN"]: ["John Doe"],
        STANDARD_ATTRIBUTES["SN"]: ["Doe"],
        STANDARD_ATTRIBUTES["GIVEN_NAME"]: ["John"],
        STANDARD_ATTRIBUTES["MAIL"]: ["john.doe@example.com"],
        "telephoneNumber": ["+1-555-123-4567"],
        "departmentNumber": ["IT"],
        "title": ["Software Engineer"],
        "employeeNumber": ["E12345"]
    }

    # Create the entry
    result = operations.add_entry(
        dn="cn=John Doe,ou=people,dc=example,dc=com",
        attributes=user_attributes
    )

    if result.success:
        print("✅ User created successfully!")
        print(f"   DN: {result.dn}")
        print(f"   Operation time: {result.operation_duration:.2f}ms")

        if result.backup_created:
            print("   💾 Backup created for rollback")

    else:
        print("❌ User creation failed!")
        print(f"   Error: {result.error_message}")
        if result.ldap_error_code:
            print(f"   LDAP Error Code: {result.ldap_error_code}")

create_user_example()
```

### Bulk User Creation

```python
def bulk_create_users_example():
    """Example of creating multiple users efficiently."""

    operations = LDAPOperations(manager)

    # User data (could come from CSV, database, etc.)
    users_data = [
        {"cn": "Alice Smith", "mail": "alice.smith@example.com", "dept": "HR"},
        {"cn": "Bob Johnson", "mail": "bob.johnson@example.com", "dept": "Finance"},
        {"cn": "Carol Davis", "mail": "carol.davis@example.com", "dept": "IT"},
        {"cn": "David Wilson", "mail": "david.wilson@example.com", "dept": "Marketing"},
        {"cn": "Eve Brown", "mail": "eve.brown@example.com", "dept": "IT"}
    ]

    # Prepare entries for bulk creation
    entries_to_create = []

    for user_data in users_data:
        dn = f"cn={user_data['cn']},ou=people,dc=example,dc=com"

        attributes = {
            "objectClass": ["person", "inetOrgPerson"],
            "cn": [user_data["cn"]],
            "sn": [user_data["cn"].split()[-1]],  # Last name
            "givenName": [user_data["cn"].split()[0]],  # First name
            "mail": [user_data["mail"]],
            "departmentNumber": [user_data["dept"]]
        }

        entries_to_create.append({
            "dn": dn,
            "attributes": attributes
        })

    # Perform bulk creation
    bulk_result = operations.bulk_add(entries_to_create)

    print(f"Bulk creation results:")
    print(f"  Total entries: {bulk_result.total_entries}")
    print(f"  Successful: {bulk_result.successful_entries}")
    print(f"  Failed: {bulk_result.failed_entries}")
    print(f"  Success rate: {bulk_result.success_rate:.1f}%")
    print(f"  Duration: {bulk_result.operation_duration:.2f}ms")
    print(f"  Performance: {bulk_result.operations_per_second:.0f} ops/second")

    # Check for failures
    if bulk_result.failed_entries > 0:
        print("\nFailed operations:")
        for op_result in bulk_result.operations_log:
            if not op_result.success:
                print(f"  ❌ {op_result.dn}: {op_result.error_message}")

    return bulk_result

bulk_create_users_example()
```

### Creating Groups

```python
def create_group_example():
    """Example of creating a group and adding members."""

    operations = LDAPOperations(manager)

    # Create the group first
    group_attributes = {
        "objectClass": ["group", "groupOfNames"],
        "cn": ["IT Team"],
        "description": ["Information Technology Team"],
        "member": [
            "cn=John Doe,ou=people,dc=example,dc=com",
            "cn=Carol Davis,ou=people,dc=example,dc=com",
            "cn=Eve Brown,ou=people,dc=example,dc=com"
        ]
    }

    group_result = operations.add_entry(
        dn="cn=IT Team,ou=groups,dc=example,dc=com",
        attributes=group_attributes
    )

    if group_result.success:
        print("✅ Group created successfully!")
        print(f"   DN: {group_result.dn}")
        print(f"   Members: {len(group_attributes['member'])}")
    else:
        print("❌ Group creation failed!")
        print(f"   Error: {group_result.error_message}")

    return group_result

create_group_example()
```

## ✏️ Updating Entries

### Modifying User Attributes

```python
def modify_user_example():
    """Example of modifying user attributes."""

    operations = LDAPOperations(manager)

    user_dn = "cn=John Doe,ou=people,dc=example,dc=com"

    # Define modifications
    modifications = {
        # Replace telephone number
        "telephoneNumber": {
            "action": "replace",
            "values": ["+1-555-999-8888"]
        },

        # Add additional email address
        "mail": {
            "action": "add",
            "values": ["j.doe@example.com"]
        },

        # Update title
        "title": {
            "action": "replace",
            "values": ["Senior Software Engineer"]
        },

        # Remove old department, add new one
        "departmentNumber": {
            "action": "replace",
            "values": ["Engineering"]
        }
    }

    result = operations.modify_entry(user_dn, modifications)

    if result.success:
        print("✅ User modified successfully!")
        print(f"   DN: {result.dn}")
        print(f"   Operation time: {result.operation_duration:.2f}ms")
        print(f"   Attributes modified: {len(result.attributes_modified)}")

        # Show what was modified
        for attr, change in result.attributes_modified.items():
            print(f"   - {attr}: {change['action']} -> {change['values']}")

    else:
        print("❌ User modification failed!")
        print(f"   Error: {result.error_message}")

modify_user_example()
```

### Batch Modifications

```python
def batch_modify_example():
    """Example of batch modifications."""

    operations = LDAPOperations(manager)

    # Batch modify multiple users - update department
    users_to_update = [
        "cn=Alice Smith,ou=people,dc=example,dc=com",
        "cn=Bob Johnson,ou=people,dc=example,dc=com",
        "cn=Carol Davis,ou=people,dc=example,dc=com"
    ]

    # Standard modification for all users
    standard_modification = {
        "departmentNumber": {
            "action": "replace",
            "values": ["New Department"]
        },
        "title": {
            "action": "replace",
            "values": ["Team Member"]
        }
    }

    # Prepare batch modifications
    batch_modifications = []
    for user_dn in users_to_update:
        batch_modifications.append({
            "dn": user_dn,
            "modifications": standard_modification
        })

    # Execute batch modifications
    batch_result = operations.bulk_modify(batch_modifications)

    print(f"Batch modification results:")
    print(f"  Total entries: {batch_result.total_entries}")
    print(f"  Successful: {batch_result.successful_entries}")
    print(f"  Failed: {batch_result.failed_entries}")
    print(f"  Success rate: {batch_result.success_rate:.1f}%")

    # Show individual results
    for op_result in batch_result.operations_log:
        status = "✅" if op_result.success else "❌"
        print(f"  {status} {op_result.dn}")
        if not op_result.success:
            print(f"      Error: {op_result.error_message}")

batch_modify_example()
```

## 🗑️ Deleting Entries

### Safe Entry Deletion

```python
def delete_entry_example():
    """Example of safely deleting entries with backup."""

    operations = LDAPOperations(manager)

    # Entry to delete
    user_dn = "cn=Test User,ou=people,dc=example,dc=com"

    # First, verify the entry exists and get its attributes for backup
    search_result = operations.search_entries(
        base_dn=user_dn,
        search_filter="(objectClass=*)",
        scope="base"  # Search only the specific entry
    )

    if search_result.entries_found == 0:
        print(f"❌ Entry not found: {user_dn}")
        return

    entry_data = search_result.entries[0]
    print(f"Found entry to delete: {entry_data.get('cn', ['Unknown'])[0]}")

    # Delete with backup
    result = operations.delete_entry(
        dn=user_dn,
        create_backup=True
    )

    if result.success:
        print("✅ Entry deleted successfully!")
        print(f"   DN: {result.dn}")
        print(f"   Operation time: {result.operation_duration:.2f}ms")

        if result.backup_created:
            print("   💾 Backup created for potential restoration")
            print(f"   Rollback data available: {bool(result.rollback_data)}")
    else:
        print("❌ Entry deletion failed!")
        print(f"   Error: {result.error_message}")

delete_entry_example()
```

### Bulk Deletion with Safety Checks

```python
def bulk_delete_example():
    """Example of bulk deletion with safety checks."""

    operations = LDAPOperations(manager)

    # Find entries to delete (e.g., inactive users)
    search_result = operations.search_entries(
        base_dn="ou=people,dc=example,dc=com",
        search_filter="(accountStatus=inactive)",
        attributes=["cn", "mail", "lastLoginTime"]
    )

    print(f"Found {search_result.entries_found} inactive users")

    if search_result.entries_found == 0:
        print("No inactive users to delete")
        return

    # Safety check - don't delete too many at once
    MAX_BULK_DELETE = 10
    if search_result.entries_found > MAX_BULK_DELETE:
        print(f"⚠️  Too many entries to delete ({search_result.entries_found})")
        print(f"   Maximum allowed: {MAX_BULK_DELETE}")
        print("   Please review the list and delete in smaller batches")
        return

    # Show what will be deleted
    print("Entries to be deleted:")
    entries_to_delete = []

    for entry in search_result.entries:
        dn = entry.get('dn')
        cn = entry.get('cn', ['Unknown'])[0]
        mail = entry.get('mail', ['No email'])[0]

        print(f"  - {cn} ({mail})")
        entries_to_delete.append({"dn": dn})

    # Confirm deletion (in real application, you might want user confirmation)
    print(f"\nDeleting {len(entries_to_delete)} entries...")

    # Perform bulk deletion
    bulk_result = operations.bulk_delete(
        entries_to_delete,
        create_backup=True
    )

    print(f"Bulk deletion results:")
    print(f"  Total entries: {bulk_result.total_entries}")
    print(f"  Successful: {bulk_result.successful_entries}")
    print(f"  Failed: {bulk_result.failed_entries}")
    print(f"  Success rate: {bulk_result.success_rate:.1f}%")

    if bulk_result.backup_created:
        print("  💾 Backups created for all deleted entries")

# Uncomment to run (be careful!)
# bulk_delete_example()
```

## 👥 User Management

### Complete User Lifecycle

```python
class UserManager:
    """Complete user management example."""

    def __init__(self, operations: LDAPOperations):
        self.operations = operations
        self.base_dn = "ou=people,dc=example,dc=com"

    def create_user(self, user_info: dict) -> bool:
        """Create a new user with standard attributes."""

        # Generate CN from first and last name
        cn = f"{user_info['first_name']} {user_info['last_name']}"
        dn = f"cn={cn},{self.base_dn}"

        # Build attributes
        attributes = {
            "objectClass": ["person", "inetOrgPerson"],
            "cn": [cn],
            "sn": [user_info["last_name"]],
            "givenName": [user_info["first_name"]],
            "mail": [user_info["email"]],
            "employeeNumber": [user_info["employee_id"]],
            "departmentNumber": [user_info["department"]],
            "title": [user_info["job_title"]]
        }

        # Optional attributes
        if "phone" in user_info:
            attributes["telephoneNumber"] = [user_info["phone"]]

        if "manager_dn" in user_info:
            attributes["manager"] = [user_info["manager_dn"]]

        # Create user
        result = self.operations.add_entry(dn, attributes)

        if result.success:
            print(f"✅ Created user: {cn}")
            return True
        else:
            print(f"❌ Failed to create user {cn}: {result.error_message}")
            return False

    def update_user(self, user_dn: str, updates: dict) -> bool:
        """Update user attributes."""

        modifications = {}

        # Handle common updates
        if "email" in updates:
            modifications["mail"] = {
                "action": "replace",
                "values": [updates["email"]]
            }

        if "phone" in updates:
            modifications["telephoneNumber"] = {
                "action": "replace",
                "values": [updates["phone"]]
            }

        if "department" in updates:
            modifications["departmentNumber"] = {
                "action": "replace",
                "values": [updates["department"]]
            }

        if "title" in updates:
            modifications["title"] = {
                "action": "replace",
                "values": [updates["title"]]
            }

        if not modifications:
            print("No valid modifications provided")
            return False

        result = self.operations.modify_entry(user_dn, modifications)

        if result.success:
            print(f"✅ Updated user: {user_dn}")
            return True
        else:
            print(f"❌ Failed to update user {user_dn}: {result.error_message}")
            return False

    def deactivate_user(self, user_dn: str) -> bool:
        """Deactivate user (mark as inactive instead of deleting)."""

        modifications = {
            "accountStatus": {
                "action": "replace",
                "values": ["inactive"]
            },
            "description": {
                "action": "add",
                "values": [f"Deactivated on {datetime.now().isoformat()}"]
            }
        }

        result = self.operations.modify_entry(user_dn, modifications)

        if result.success:
            print(f"✅ Deactivated user: {user_dn}")
            return True
        else:
            print(f"❌ Failed to deactivate user {user_dn}: {result.error_message}")
            return False

    def find_user_by_email(self, email: str) -> dict | None:
        """Find user by email address."""

        result = self.operations.search_entries(
            base_dn=self.base_dn,
            search_filter=f"(mail={email})",
            attributes=["cn", "mail", "employeeNumber", "departmentNumber"]
        )

        if result.entries_found > 0:
            return result.entries[0]
        else:
            return None

    def list_users_by_department(self, department: str) -> list:
        """List all users in a department."""

        result = self.operations.search_entries(
            base_dn=self.base_dn,
            search_filter=f"(departmentNumber={department})",
            attributes=["cn", "mail", "title", "telephoneNumber"]
        )

        return result.entries

# Usage example
def user_management_example():
    """Complete user management workflow."""

    operations = LDAPOperations(manager)
    user_mgr = UserManager(operations)

    # 1. Create a new user
    new_user = {
        "first_name": "Jane",
        "last_name": "Smith",
        "email": "jane.smith@example.com",
        "employee_id": "E54321",
        "department": "Marketing",
        "job_title": "Marketing Specialist",
        "phone": "+1-555-123-9999"
    }

    user_mgr.create_user(new_user)

    # 2. Find the user
    user_entry = user_mgr.find_user_by_email("jane.smith@example.com")
    if user_entry:
        print(f"Found user: {user_entry.get('cn', [''])[0]}")
        user_dn = user_entry.get('dn')

        # 3. Update the user
        updates = {
            "title": "Senior Marketing Specialist",
            "phone": "+1-555-123-0000"
        }
        user_mgr.update_user(user_dn, updates)

        # 4. Later, deactivate the user
        # user_mgr.deactivate_user(user_dn)

    # 5. List users by department
    marketing_users = user_mgr.list_users_by_department("Marketing")
    print(f"Marketing department has {len(marketing_users)} users")

# Run the example
user_management_example()
```

This is an extensive start to the usage examples. The documentation covers basic operations, configuration, connections, and user management with practical, real-world examples. Each example includes error handling, best practices, and detailed explanations.

Would you like me to continue with the remaining sections (Group Management, LDIF Operations, Schema Management, Performance Optimization, etc.) to complete this comprehensive usage guide?

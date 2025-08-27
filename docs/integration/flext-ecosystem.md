# FLEXT Ecosystem Integration

**Complete Integration Guide for FLEXT Data Platform**

FLEXT-LDAP serves as a core infrastructure component in the FLEXT data platform ecosystem, providing enterprise-grade LDAP directory services with seamless integration across all platform components.

---

## 🏗️ Ecosystem Overview

### FLEXT Platform Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              FLEXT Data Platform                             │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐              │
│  │   FlexCore      │  │ FLEXT Service   │  │   flext-web     │              │
│  │   (Go Runtime)  │  │ (Go/Python)     │  │   (Dashboard)   │              │
│  │   Port 8080     │  │   Port 8081     │  │   Port 3000     │              │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘              │
├─────────────────────────────────────────────────────────────────────────────┤
│                          Application Services                               │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐              │
│  │   flext-api     │  │   flext-auth    │  │   flext-cli     │              │
│  │   (REST API)    │  │ (Authentication)│  │ (Command Tools) │              │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘              │
├─────────────────────────────────────────────────────────────────────────────┤
│                        Infrastructure Libraries                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐              │
│  │   FLEXT-LDAP    │  │ flext-db-oracle │  │  flext-grpc     │              │
│  │ ◄── THIS ──────►│  │  (Oracle DB)    │  │ (Communication) │              │
│  │ (LDAP Services) │  │                 │  │                 │              │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘              │
├─────────────────────────────────────────────────────────────────────────────┤
│                           Singer Ecosystem                                  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐              │
│  │ flext-tap-ldap  │  │flext-target-ldap│  │ flext-dbt-ldap  │              │
│  │ (Extract LDAP)  │  │ (Load to LDAP)  │  │ (Transform)     │              │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘              │
├─────────────────────────────────────────────────────────────────────────────┤
│                         Foundation Layer                                    │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐              │
│  │   flext-core    │  │flext-observability│ │  flext-meltano  │              │
│  │   (Patterns)    │  │  (Monitoring)   │  │ (Orchestration) │              │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔗 Core Dependencies

### flext-core Integration

**FlextResult Pattern**

```python
from flext_core import FlextResult, get_logger
from flext_ldap import get_ldap_api

logger = get_logger(__name__)

async def integrate_with_core():
    \"\"\"Example of FlextResult pattern integration.\"\"\"
    api = get_ldap_api()

    # All operations return FlextResult for consistent error handling
    result = await api.search(session, \"ou=users,dc=company,dc=com\", \"(uid=*)\")

    if result.success:
        logger.info(f\"Found {len(result.data)} users\")
        return result.data
    else:
        logger.error(f\"LDAP search failed: {result.error}\")
        return []
```

**Dependency Injection Container**

```python
from flext_core import FlextContainer, get_flext_container
from flext_ldap import FlextLdapService, FlextLdapUserRepository

# Container configuration
container = FlextContainer.get_global()

# Register LDAP services with the container
container.register_singleton(
    FlextLdapUserRepository,
    FlextLdapUserRepositoryImpl
)

container.register_transient(FlextLdapService)

# Resolve services with full dependency injection
ldap_service = container.resolve(FlextLdapService)
```

**Centralized Configuration**

```python
from flext_core import FlextLDAPConfig
from flext_ldap import FlextLdapSettings

# Use centralized configuration from flext-core
ldap_config = FlextLDAPConfig()

# Local settings extend core configuration
local_settings = FlextLdapSettings(
    server_url=ldap_config.server_url,
    port=ldap_config.port,
    use_ssl=ldap_config.use_ssl
)
```

### flext-observability Integration

**Structured Logging**

```python
from flext_observability import get_logger, LogContext
from flext_ldap import get_ldap_api

logger = get_logger(__name__)

async def ldap_operation_with_logging():
    \"\"\"LDAP operations with structured logging.\"\"\"

    with LogContext(operation=\"ldap_user_search\", trace_id=\"abc-123\"):
        logger.info(\"Starting LDAP user search\")

        api = get_ldap_api()
        async with api.connection(...) as session:
            result = await api.search(session, base_dn, filter_expr)

            if result.success:
                logger.info(
                    \"LDAP search completed successfully\",
                    extra={
                        \"user_count\": len(result.data),
                        \"search_time_ms\": 150,
                        \"ldap_server\": \"ldap.company.com\"
                    }
                )
            else:
                logger.error(
                    \"LDAP search failed\",
                    extra={
                        \"error\": result.error,
                        \"base_dn\": base_dn,
                        \"filter\": filter_expr
                    }
                )
```

**Metrics Collection**

```python
from flext_observability import get_metrics_client
from flext_ldap import get_ldap_api

metrics = get_metrics_client()

async def ldap_operation_with_metrics():
    \"\"\"LDAP operations with automatic metrics collection.\"\"\"

    with metrics.timer(\"ldap_operation_duration\"):
        api = get_ldap_api()

        # Metrics automatically collected:
        # - ldap_connections_total
        # - ldap_operations_total
        # - ldap_errors_total
        # - ldap_response_time_seconds

        result = await api.create_user(session, user_request)

        if result.success:
            metrics.increment(\"ldap_user_created_total\")
        else:
            metrics.increment(\"ldap_user_creation_errors_total\")
```

**Health Checks**

```python
from flext_observability import HealthCheckRegistry
from flext_ldap import get_ldap_api

health_registry = HealthCheckRegistry()

@health_registry.register(\"ldap_connectivity\")
async def check_ldap_health():
    \"\"\"Health check for LDAP connectivity.\"\"\"
    try:
        api = get_ldap_api()

        # Test connection
        async with api.connection(
            \"ldap://directory.company.com\",
            \"cn=health,ou=service,dc=company,dc=com\",
            \"health_check_password\"
        ) as session:
            # Simple search to verify connectivity
            result = await api.search(session, \"dc=company,dc=com\", \"(objectClass=organization)\")

            if result.success:
                return {\"status\": \"healthy\", \"response_time_ms\": 45}
            else:
                return {\"status\": \"unhealthy\", \"error\": result.error}

    except Exception as e:
        return {\"status\": \"unhealthy\", \"error\": str(e)}
```

---

## 🔄 Singer Ecosystem Integration

### flext-tap-ldap (Data Extraction)

**Tap Configuration**

```python
from flext_tap_ldap import FlextLdapTap
from flext_ldap import get_ldap_api

# Configure LDAP tap for data extraction
tap_config = {
    \"server_url\": \"ldap://directory.company.com\",
    \"bind_dn\": \"cn=etl,ou=service,dc=company,dc=com\",
    \"bind_password\": \"etl_password\",
    \"base_dn\": \"dc=company,dc=com\",
    \"schemas\": [
        {
            \"name\": \"users\",
            \"base_dn\": \"ou=users,dc=company,dc=com\",
            \"filter\": \"(objectClass=person)\",
            \"attributes\": [\"uid\", \"cn\", \"sn\", \"mail\", \"departmentNumber\"]
        },
        {
            \"name\": \"groups\",
            \"base_dn\": \"ou=groups,dc=company,dc=com\",
            \"filter\": \"(objectClass=group)\",
            \"attributes\": [\"cn\", \"member\", \"description\"]
        }
    ]
}

# Initialize tap with FLEXT-LDAP integration
tap = FlextLdapTap(config=tap_config)
tap.set_ldap_provider(get_ldap_api())  # Use FLEXT-LDAP as provider
```

**Schema Discovery**

```python
async def discover_ldap_schemas():
    \"\"\"Automatically discover LDAP schemas for Singer catalog.\"\"\"

    api = get_ldap_api()

    async with api.connection(...) as session:
        # Discover organizational units
        ou_result = await api.search(
            session,
            \"dc=company,dc=com\",
            \"(objectClass=organizationalUnit)\"
        )

        schemas = []
        for ou in ou_result.data:
            # Analyze object classes in each OU
            objects_result = await api.search(
                session,
                ou.dn,
                \"(objectClass=*)\",
                attributes=[\"objectClass\"]
            )

            # Generate Singer schema from LDAP object classes
            schema = generate_singer_schema(ou, objects_result.data)
            schemas.append(schema)

        return schemas

def generate_singer_schema(ou, objects):
    \"\"\"Generate Singer schema from LDAP object analysis.\"\"\"
    return {
        \"stream\": ou.cn,
        \"tap_stream_id\": ou.dn,
        \"schema\": {
            \"type\": \"object\",
            \"properties\": analyze_ldap_attributes(objects)
        },
        \"metadata\": {
            \"inclusion\": \"available\",
            \"selected\": True
        }
    }
```

### flext-target-ldap (Data Loading)

**Target Configuration**

```python
from flext_target_ldap import FlextLdapTarget
from flext_ldap import get_ldap_api

target_config = {
    \"server_url\": \"ldap://target.company.com\",
    \"bind_dn\": \"cn=loader,ou=service,dc=company,dc=com\",
    \"bind_password\": \"loader_password\",
    \"default_base_dn\": \"ou=imported,dc=company,dc=com\",
    \"mapping_rules\": {
        \"users\": {
            \"dn_template\": \"uid={uid},ou=users,dc=company,dc=com\",
            \"object_classes\": [\"person\", \"organizationalPerson\", \"inetOrgPerson\"],
            \"attribute_mapping\": {
                \"user_id\": \"uid\",
                \"full_name\": \"cn\",
                \"last_name\": \"sn\",
                \"email\": \"mail\"
            }
        }
    }
}

# Initialize target with FLEXT-LDAP integration
target = FlextLdapTarget(config=target_config)
target.set_ldap_provider(get_ldap_api())  # Use FLEXT-LDAP as provider
```

**Data Loading Pipeline**

```python
async def load_data_to_ldap(singer_records):
    \"\"\"Load Singer records to LDAP directory.\"\"\"

    api = get_ldap_api()

    async with api.connection(...) as session:
        for record in singer_records:
            # Apply mapping rules
            ldap_entry = apply_mapping_rules(record)

            # Create LDAP entry
            result = await api.create_entry(session, ldap_entry)

            if result.success:
                logger.info(f\"Created LDAP entry: {ldap_entry.dn}\")
            else:
                logger.error(f\"Failed to create entry: {result.error}\")
```

### flext-dbt-ldap (Data Transformation)

**DBT Models for LDAP Data**

```sql
-- models/ldap_users_normalized.sql
{{
  config(
    materialized='table',
    post_hook=\"SELECT flext_ldap_sync('{{ this }}')\"
  )
}}

WITH source_users AS (
    SELECT
        uid,
        cn as full_name,
        sn as last_name,
        mail as email,
        departmentNumber as department_id,
        _sdc_extracted_at as extracted_at
    FROM {{ source('ldap', 'users') }}
),

normalized_users AS (
    SELECT
        uid,
        TRIM(full_name) as full_name,
        TRIM(last_name) as last_name,
        LOWER(TRIM(email)) as email,
        CAST(department_id AS INTEGER) as department_id,
        extracted_at
    FROM source_users
    WHERE uid IS NOT NULL
      AND full_name IS NOT NULL
      AND email IS NOT NULL
)

SELECT * FROM normalized_users
```

**LDAP-Specific DBT Macros**

```sql
-- macros/ldap_dn_parser.sql
{% macro parse_ldap_dn(dn_column) %}
    REGEXP_EXTRACT({{ dn_column }}, r'cn=([^,]+)', 1) as cn,
    REGEXP_EXTRACT({{ dn_column }}, r'ou=([^,]+)', 1) as ou,
    REGEXP_EXTRACT({{ dn_column }}, r'dc=([^,]+)', 1) as dc
{% endmacro %}

-- macros/flext_ldap_sync.sql
{% macro flext_ldap_sync(model_ref) %}
    -- Custom macro to sync DBT model results back to LDAP
    -- Integrates with FLEXT-LDAP for bidirectional sync
{% endmacro %}
```

---

## 🔐 Authentication Integration

### flext-auth Service Integration

**LDAP Authentication Provider**

```python
from flext_auth import AuthenticationService, AuthProvider
from flext_ldap import get_ldap_api

class FlextLdapAuthProvider(AuthProvider):
    \"\"\"LDAP authentication provider for flext-auth.\"\"\"

    def __init__(self):
        self.ldap_api = get_ldap_api()

    async def authenticate(
        self,
        username: str,
        password: str
    ) -> FlextResult[AuthUser]:
        \"\"\"Authenticate user against LDAP directory.\"\"\"

        try:
            # Attempt LDAP bind with user credentials
            user_dn = f\"uid={username},ou=users,dc=company,dc=com\"

            async with self.ldap_api.connection(
                \"ldap://auth.company.com\",
                user_dn,
                password
            ) as session:
                # Successful bind means valid credentials
                # Fetch user details
                user_result = await self.ldap_api.search(
                    session,
                    user_dn,
                    \"(objectClass=person)\",
                    attributes=[\"uid\", \"cn\", \"mail\", \"memberOf\"]
                )

                if user_result.success and user_result.data:
                    user_entry = user_result.data[0]

                    # Convert LDAP user to AuthUser
                    auth_user = AuthUser(
                        id=user_entry.uid,
                        username=user_entry.uid,
                        display_name=user_entry.cn,
                        email=user_entry.mail,
                        roles=self._extract_roles_from_groups(user_entry.member_of)
                    )

                    return FlextResult[None].ok(auth_user)

                return FlextResult[None].fail(\"User details not found\")

        except Exception as e:
            return FlextResult[None].fail(f\"Authentication failed: {str(e)}\")

    def _extract_roles_from_groups(self, groups: List[str]) -> List[str]:
        \"\"\"Extract roles from LDAP group memberships.\"\"\"
        roles = []
        for group_dn in groups:
            # Extract role from group CN
            if \"cn=admin\" in group_dn.lower():
                roles.append(\"admin\")
            elif \"cn=editor\" in group_dn.lower():
                roles.append(\"editor\")
            elif \"cn=viewer\" in group_dn.lower():
                roles.append(\"viewer\")
        return roles

# Register LDAP provider with flext-auth
auth_service = AuthenticationService()
auth_service.register_provider(\"ldap\", FlextLdapAuthProvider())
```

**Single Sign-On Integration**

```python
from flext_auth import SSOService
from flext_ldap import get_ldap_api

class FlextLdapSSOProvider:
    \"\"\"SSO provider using LDAP directory.\"\"\"

    async def validate_sso_token(self, token: str) -> FlextResult[AuthUser]:
        \"\"\"Validate SSO token against LDAP directory.\"\"\"

        # Parse token to extract user information
        token_data = self._parse_sso_token(token)

        if not token_data:
            return FlextResult[None].fail(\"Invalid SSO token\")

        # Verify user exists in LDAP
        api = get_ldap_api()
        async with api.connection(...) as session:
            user_result = await api.search(
                session,
                f\"ou=users,dc=company,dc=com\",
                f\"(uid={token_data.username})\",
                attributes=[\"uid\", \"cn\", \"mail\", \"memberOf\"]
            )

            if user_result.success and user_result.data:
                # User exists, create AuthUser
                return self._create_auth_user(user_result.data[0])
            else:
                return FlextResult[None].fail(\"User not found in directory\")
```

---

## 📊 Data Format Integration

### flext-ldif Integration

**LDIF Export/Import**

```python
from flext_ldif import FlextLdifProcessor, LdifEntry
from flext_ldap import get_ldap_api

async def export_ldap_to_ldif():
    \"\"\"Export LDAP directory data to LDIF format.\"\"\"

    api = get_ldap_api()
    ldif_processor = FlextLdifProcessor()

    async with api.connection(...) as session:
        # Export users
        users_result = await api.search(
            session,
            \"ou=users,dc=company,dc=com\",
            \"(objectClass=person)\",
            attributes=[\"*\"]
        )

        if users_result.success:
            # Convert LDAP entries to LDIF format
            ldif_entries = []
            for user in users_result.data:
                ldif_entry = LdifEntry(
                    dn=user.dn,
                    attributes=user.attributes
                )
                ldif_entries.append(ldif_entry)

            # Generate LDIF content
            ldif_content = ldif_processor.generate_ldif(ldif_entries)

            # Save to file
            with open(\"directory_export.ldif\", \"w\") as f:
                f.write(ldif_content)

            return FlextResult[None].ok(f\"Exported {len(ldif_entries)} entries\")

async def import_ldif_to_ldap(ldif_file_path: str):
    \"\"\"Import LDIF file to LDAP directory.\"\"\"

    api = get_ldap_api()
    ldif_processor = FlextLdifProcessor()

    # Parse LDIF file
    ldif_entries = ldif_processor.parse_ldif_file(ldif_file_path)

    async with api.connection(...) as session:
        for entry in ldif_entries:
            # Convert LDIF entry to LDAP entry
            result = await api.create_entry(session, entry)

            if result.success:
                logger.info(f\"Imported entry: {entry.dn}\")
            else:
                logger.error(f\"Failed to import {entry.dn}: {result.error}\")
```

---

## 🚀 Service Communication

### FlexCore ↔ FLEXT Service Integration

**Plugin Architecture**

```python
# FlexCore plugin registration
from flexcore.plugins import FlextPlugin
from flext_ldap import get_ldap_api

class FlextLdapPlugin(FlextPlugin):
    \"\"\"LDAP plugin for FlexCore runtime.\"\"\"

    def __init__(self):
        self.name = \"flext-ldap\"
        self.version = \"0.9.0\"
        self.ldap_api = get_ldap_api()

    async def execute(self, operation: str, params: dict) -> FlextResult:
        \"\"\"Execute LDAP operations via FlexCore.\"\"\"

        if operation == \"search_users\":
            return await self._search_users(params)
        elif operation == \"create_user\":
            return await self._create_user(params)
        elif operation == \"health_check\":
            return await self._health_check()
        else:
            return FlextResult[None].fail(f\"Unknown operation: {operation}\")

    async def _search_users(self, params: dict) -> FlextResult:
        \"\"\"Search users operation.\"\"\"
        async with self.ldap_api.connection(...) as session:
            return await self.ldap_api.search(
                session,
                params.get(\"base_dn\", \"ou=users,dc=company,dc=com\"),
                params.get(\"filter\", \"(objectClass=person)\")
            )

# Register plugin with FlexCore
flexcore_registry.register_plugin(FlextLdapPlugin())
```

**HTTP API Integration**

```python
# FLEXT Service HTTP endpoint
from flext_service import app
from flext_ldap import get_ldap_api

@app.post(\"/api/v1/ldap/users/search\")
async def search_ldap_users(request: SearchUsersRequest):
    \"\"\"Search LDAP users via HTTP API.\"\"\"

    api = get_ldap_api()

    async with api.connection(
        request.server_url,
        request.bind_dn,
        request.bind_password
    ) as session:
        result = await api.search(
            session,
            request.base_dn,
            request.filter,
            request.attributes
        )

        if result.success:
            return {
                \"status\": \"success\",
                \"data\": [user.to_dict() for user in result.data],
                \"count\": len(result.data)
            }
        else:
            return {
                \"status\": \"error\",
                \"error\": result.error
            }
```

---

## 📈 Monitoring & Observability

### Comprehensive Monitoring Integration

**Distributed Tracing**

```python
from flext_observability import get_tracer
from flext_ldap import get_ldap_api

tracer = get_tracer(__name__)

async def traced_ldap_operation():
    \"\"\"LDAP operation with distributed tracing.\"\"\"

    with tracer.start_as_current_span(\"ldap_user_operation\") as span:
        span.set_attributes({
            \"ldap.server\": \"directory.company.com\",
            \"ldap.operation\": \"search_users\",
            \"ldap.base_dn\": \"ou=users,dc=company,dc=com\"
        })

        api = get_ldap_api()

        with tracer.start_as_current_span(\"ldap_connection\") as conn_span:
            async with api.connection(...) as session:
                conn_span.set_attribute(\"ldap.connection_time_ms\", 120)

                with tracer.start_as_current_span(\"ldap_search\") as search_span:
                    result = await api.search(session, ...)

                    search_span.set_attributes({
                        \"ldap.results_count\": len(result.data) if result.success else 0,
                        \"ldap.search_time_ms\": 450,
                        \"ldap.success\": result.success
                    })

                    return result
```

**Custom Metrics**

```python
from flext_observability import get_metrics_client
from prometheus_client import Counter, Histogram, Gauge

# Custom LDAP metrics
ldap_operations_total = Counter(
    \"flext_ldap_operations_total\",
    \"Total LDAP operations\",
    [\"operation\", \"server\", \"status\"]
)

ldap_response_time = Histogram(
    \"flext_ldap_response_time_seconds\",
    \"LDAP operation response time\",
    [\"operation\", \"server\"]
)

ldap_active_connections = Gauge(
    \"flext_ldap_active_connections\",
    \"Number of active LDAP connections\",
    [\"server\"]
)

async def monitored_ldap_operation():
    \"\"\"LDAP operation with custom metrics.\"\"\"

    with ldap_response_time.labels(operation=\"search\", server=\"ldap.company.com\").time():
        try:
            result = await api.search(...)

            ldap_operations_total.labels(
                operation=\"search\",
                server=\"ldap.company.com\",
                status=\"success\" if result.success else \"failure\"
            ).inc()

            return result

        except Exception as e:
            ldap_operations_total.labels(
                operation=\"search\",
                server=\"ldap.company.com\",
                status=\"error\"
            ).inc()
            raise
```

---

## 🔧 Configuration Management

### Centralized Configuration

**Environment-Based Configuration**

```python
# Production configuration
FLEXT_LDAP_HOST=ldap-prod.company.com
FLEXT_LDAP_PORT=636
FLEXT_LDAP_USE_SSL=true
FLEXT_LDAP_BIND_DN=cn=prod-service,ou=applications,dc=company,dc=com
FLEXT_LDAP_BIND_PASSWORD=<secure-password>

# Integration settings
FLEXT_LDAP_ENABLE_METRICS=true
FLEXT_LDAP_ENABLE_TRACING=true
FLEXT_LDAP_CONNECTION_POOL_SIZE=10
FLEXT_LDAP_RETRY_ATTEMPTS=3

# Ecosystem integration
FLEXT_SINGER_LDAP_CATALOG_PATH=/etc/flext/ldap-catalog.json
FLEXT_AUTH_LDAP_PROVIDER_ENABLED=true
FLEXT_LDIF_EXPORT_PATH=/var/flext/ldap-exports/
```

**Configuration Validation**

```python
from flext_core import FlextLDAPConfig
from flext_ldap import FlextLdapSettings

def validate_ecosystem_configuration():
    \"\"\"Validate FLEXT ecosystem configuration.\"\"\"

    # Core configuration
    core_config = FlextLDAPConfig()

    # LDAP-specific configuration
    ldap_config = FlextLdapSettings()

    # Validation checks
    if not core_config.is_valid():
        raise ConfigurationError(\"Invalid core LDAP configuration\")

    if not ldap_config.server_url:
        raise ConfigurationError(\"LDAP server URL is required\")

    # Cross-service validation
    if ldap_config.enable_auth_integration:
        auth_config = get_auth_config()
        if not auth_config.ldap_provider_enabled:
            raise ConfigurationError(\"Auth service LDAP provider must be enabled\")

    return True
```

---

_This integration guide is part of the FLEXT-LDAP documentation and follows FLEXT Framework integration standards._

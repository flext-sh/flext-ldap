# Integration Guide

**Integrating flext-ldap with FLEXT ecosystem and external systems**

This guide covers integration patterns, FLEXT ecosystem usage, and third-party system integration.

---

## FLEXT Ecosystem Integration

### Core FLEXT Dependencies

FLEXT-LDAP builds on established FLEXT foundation patterns:

```python
# FLEXT-Core integration
from flext_core import FlextResult, FlextLogger, FlextContainer
from flext_ldap import get_flext_ldap_api

class UserService:
    """Service using FLEXT patterns with LDAP operations."""

    def __init__(self) -> None:
        self._logger = FlextLogger(__name__)
        self._ldap_api = get_flext_ldap_api()
        self._container = FlextContainer.get_global()

    def process_user_authentication(self, username: str, password: str) -> FlextResult[dict]:
        """Process authentication using FLEXT + LDAP patterns."""
        self._logger.info("Processing user authentication", extra={"username": username})

        auth_result = self._ldap_api.authenticate_user(username, password)
        if auth_result.is_failure:
            self._logger.error("Authentication failed", extra={"error": auth_result.error})
            return FlextResult[dict].fail(f"Authentication failed: {auth_result.error}")

        user = auth_result.unwrap()
        self._logger.info("User authenticated successfully", extra={"uid": user.uid})

        return FlextResult[dict].ok({
            "uid": user.uid,
            "cn": user.cn,
            "email": user.mail,
            "groups": user.member_of
        })
```

### Configuration Management

```python
# Environment-based configuration following FLEXT patterns
from Flext_ldap import FlextLdapConfig
from pydantic import BaseSettings

class AppSettings(BaseSettings):
    """Application settings with LDAP configuration."""

    # LDAP connection settings
    ldap_host: str = "ldap.example.com"
    ldap_port: int = 636
    ldap_use_ssl: bool = True
    ldap_bind_dn: str = "cn=service,dc=example,dc=com"
    ldap_bind_password: str = ""
    ldap_base_dn: str = "dc=example,dc=com"

    # Application settings
    app_name: str = "flext-app"
    debug: bool = False

    def get_ldap_config(self) -> FlextLdapConfig:
        """Create LDAP configuration from app settings."""
        return FlextLdapConfig(
            host=self.ldap_host,
            port=self.ldap_port,
            use_ssl=self.ldap_use_ssl,
            bind_dn=self.ldap_bind_dn,
            bind_password=self.ldap_bind_password,
            base_dn=self.ldap_base_dn
        )

# Usage in FLEXT applications
settings = AppSettings()
ldap_config = settings.get_ldap_config()
```

---

## FastAPI Integration

### API Endpoints with LDAP Authentication

```python
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from flext_ldap import get_flext_ldap_api, FlextLdapEntities
from flext_core import FlextResult

app = FastAPI(title="FLEXT LDAP API")
security = HTTPBearer()

def authenticate_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Dependency for LDAP-based token authentication."""
    # Token validation logic here
    return credentials.credentials

@app.post("/auth/login")
def login(username: str, password: str) -> dict:
    """User login endpoint with LDAP authentication."""
    ldap_api = get_flext_ldap_api()

    auth_result = ldap_api.authenticate_user(username, password)
    if auth_result.is_failure:
        raise HTTPException(status_code=401, detail=auth_result.error)

    user = auth_result.unwrap()
    return {
        "user_id": user.uid,
        "display_name": user.cn,
        "email": user.mail,
        "groups": user.member_of
    }

@app.get("/users/search")
def search_users(
    filter_str: str = "(objectClass=person)",
    limit: int = 100,
    token: str = Depends(authenticate_token)
) -> dict:
    """Search users endpoint with LDAP integration."""
    ldap_api = get_flext_ldap_api()

    search_request = FlextLdapEntities.SearchRequest(
        base_dn="ou=users,dc=example,dc=com",
        filter_str=filter_str,
        scope="subtree",
        attributes=["uid", "cn", "mail", "memberOf"],
        size_limit=limit
    )

    result = ldap_api.search_entries(search_request)
    if result.is_failure:
        raise HTTPException(status_code=500, detail=result.error)

    entries = result.unwrap()
    return {
        "users": [
            {
                "uid": entry.uid,
                "name": entry.cn,
                "email": entry.mail,
                "groups": entry.member_of or []
            }
            for entry in entries
        ],
        "count": len(entries)
    }

@app.post("/users/create")
def create_user(
    user_data: dict,
    token: str = Depends(authenticate_token)
) -> dict:
    """Create user endpoint with LDAP integration."""
    ldap_api = get_flext_ldap_api()

    create_request = FlextLdapEntities.CreateUserRequest(
        dn=f"cn={user_data['uid']},ou=users,dc=example,dc=com",
        uid=user_data["uid"],
        cn=user_data["cn"],
        sn=user_data["sn"],
        mail=user_data.get("mail"),
        object_classes=["person", "organizationalPerson", "inetOrgPerson"]
    )

    result = ldap_api.create_user(create_request)
    if result.is_failure:
        raise HTTPException(status_code=400, detail=result.error)

    user = result.unwrap()
    return {
        "message": "User created successfully",
        "user": {
            "uid": user.uid,
            "dn": user.dn,
            "name": user.cn
        }
    }
```

---

## Django Integration

### Django Authentication Backend

```python
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User
from flext_ldap import get_flext_ldap_api

class FlextLdapBackend(BaseBackend):
    """Django authentication backend using FLEXT-LDAP."""

    def authenticate(self, request, username=None, password=None, **kwargs):
        """Authenticate user against LDAP directory."""
        if not username or not password:
            return None

        # Run LDAP authentication
        try:
            ldap_api = get_flext_ldap_api()
            auth_result = run(ldap_api.authenticate_user(username, password))

            if auth_result.is_failure:
                return None

            ldap_user = auth_result.unwrap()

            # Get or create Django user
            user, created = User.objects.get_or_create(
                username=ldap_user.uid,
                defaults={
                    'first_name': ldap_user.given_name or '',
                    'last_name': ldap_user.sn or '',
                    'email': ldap_user.mail or '',
                    'is_staff': self._is_staff_user(ldap_user),
                    'is_active': True
                }
            )

            if not created:
                # Update existing user info
                user.first_name = ldap_user.given_name or user.first_name
                user.last_name = ldap_user.sn or user.last_name
                user.email = ldap_user.mail or user.email
                user.is_staff = self._is_staff_user(ldap_user)
                user.save()

            return user

        except Exception as e:
            # Log error appropriately
            return None

    def get_user(self, user_id):
        """Get user by ID."""
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def _is_staff_user(self, ldap_user) -> bool:
        """Check if LDAP user should have staff privileges."""
        staff_groups = ['cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com']
        return any(group in ldap_user.member_of for group in staff_groups)

# settings.py
AUTHENTICATION_BACKENDS = [
    'myapp.auth.FlextLdapBackend',
    'django.contrib.auth.backends.ModelBackend',
]
```

### Django User Sync Management Command

```python
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from flext_ldap import get_flext_ldap_api, FlextLdapEntities

class Command(BaseCommand):
    """Sync users from LDAP to Django database."""

    help = 'Synchronize users from LDAP directory'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be synced without making changes'
        )

    def handle(self, *args, **options):
        """Handle the sync command."""
        run(self._sync_users(options['dry_run']))

    def _sync_users(self, dry_run: bool):
        """Perform user synchronization."""
        ldap_api = get_flext_ldap_api()

        # Search for all users
        search_request = FlextLdapEntities.SearchRequest(
            base_dn="ou=users,dc=example,dc=com",
            filter_str="(objectClass=person)",
            scope="subtree",
            attributes=["uid", "cn", "sn", "givenName", "mail", "memberOf"]
        )

        result = ldap_api.search_entries(search_request)
        if result.is_failure:
            self.stdout.write(
                self.style.ERROR(f'LDAP search failed: {result.error}')
            )
            return

        ldap_users = result.unwrap()
        synced_count = 0
        created_count = 0

        for ldap_user in ldap_users:
            try:
                user, created = User.objects.get_or_create(
                    username=ldap_user.uid,
                    defaults={
                        'first_name': ldap_user.given_name or '',
                        'last_name': ldap_user.sn or '',
                        'email': ldap_user.mail or '',
                        'is_active': True
                    }
                )

                if not dry_run:
                    if created:
                        created_count += 1
                        self.stdout.write(f'Created user: {user.username}')
                    else:
                        # Update existing user
                        updated = False
                        if user.first_name != (ldap_user.given_name or ''):
                            user.first_name = ldap_user.given_name or ''
                            updated = True
                        if user.last_name != (ldap_user.sn or ''):
                            user.last_name = ldap_user.sn or ''
                            updated = True
                        if user.email != (ldap_user.mail or ''):
                            user.email = ldap_user.mail or ''
                            updated = True

                        if updated:
                            user.save()
                            self.stdout.write(f'Updated user: {user.username}')

                synced_count += 1

            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'Error syncing user {ldap_user.uid}: {e}')
                )

        if dry_run:
            self.stdout.write(
                self.style.SUCCESS(f'Dry run: Would sync {synced_count} users')
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(
                    f'Synced {synced_count} users ({created_count} created)'
                )
            )
```

---

## Flask Integration

### Flask Application with LDAP Authentication

```python
from flask import Flask, request, jsonify, g
from functools import wraps
from flext_ldap import get_flext_ldap_api, FlextLdapEntities

app = Flask(__name__)

def route(f):
    """Decorator to handle routes in Flask."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        loop = new_event_loop()
        set_event_loop(loop)
        try:
            return loop.run_until_complete(f(*args, **kwargs))
        finally:
            loop.close()
    return wrapper

def require_auth(f):
    """Decorator for routes requiring authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def check_auth(username: str, password: str) -> bool:
    """Check username/password against LDAP."""
    ldap_api = get_flext_ldap_api()

    loop = new_event_loop()
    set_event_loop(loop)
    try:
        auth_result = loop.run_until_complete(
            ldap_api.authenticate_user(username, password)
        )
        return auth_result.is_success
    finally:
        loop.close()

@app.route('/api/users/search')
@require_auth
@route
def search_users():
    """Search users endpoint."""
    filter_str = request.args.get('filter', '(objectClass=person)')
    limit = int(request.args.get('limit', 100))

    ldap_api = get_flext_ldap_api()

    search_request = FlextLdapEntities.SearchRequest(
        base_dn="ou=users,dc=example,dc=com",
        filter_str=filter_str,
        scope="subtree",
        attributes=["uid", "cn", "mail"],
        size_limit=limit
    )

    result = ldap_api.search_entries(search_request)
    if result.is_failure:
        return jsonify({'error': result.error}), 500

    entries = result.unwrap()
    return jsonify({
        'users': [
            {
                'uid': entry.uid,
                'name': entry.cn,
                'email': entry.mail
            }
            for entry in entries
        ]
    })

if __name__ == '__main__':
    app.run(debug=True)
```

---

## Docker Integration

### Docker Compose Setup

```yaml
# docker-compose.yml
version: "3.8"

services:
  app:
    build: .
    environment:
      - FLEXT_LDAP_HOST=ldap-server
      - FLEXT_LDAP_PORT=389
      - FLEXT_LDAP_BIND_DN=cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com
      - FLEXT_LDAP_BIND_PASSWORD=REDACTED_LDAP_BIND_PASSWORD
      - FLEXT_LDAP_BASE_DN=dc=example,dc=com
    depends_on:
      - ldap-server
    ports:
      - "8000:8000"

  ldap-server:
    image: osixia/openldap:1.5.0
    environment:
      - LDAP_ORGANISATION=Example Corp
      - LDAP_DOMAIN=example.com
      - LDAP_ADMIN_PASSWORD=REDACTED_LDAP_BIND_PASSWORD
    ports:
      - "389:389"
      - "636:636"
    volumes:
      - ldap_data:/var/lib/ldap
      - ldap_config:/etc/ldap/slapd.d

  ldap-REDACTED_LDAP_BIND_PASSWORD:
    image: osixia/phpldapREDACTED_LDAP_BIND_PASSWORD:latest
    environment:
      - PHPLDAPADMIN_LDAP_HOSTS=ldap-server
    ports:
      - "8080:80"
    depends_on:
      - ldap-server

volumes:
  ldap_data:
  ldap_config:
```

### Dockerfile with FLEXT-LDAP

```dockerfile
FROM python:3.13-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libldap2-dev \
    libsasl2-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml poetry.lock ./
RUN pip install poetry && \
    poetry config virtualenvs.create false && \
    poetry install --no-dev

# Copy application
COPY . .

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "from flext_ldap import get_flext_ldap_api; import  run(get_flext_ldap_api().test_connection())"

EXPOSE 8000

CMD ["python", "-m", "myapp"]
```

---

## Kubernetes Integration

### Kubernetes Deployment

```yaml
# k8s-deployment.yml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: flext-ldap-app
spec:
  replicas: 3
  selector:
    matchLabels:
      app: flext-ldap-app
  template:
    metadata:
      labels:
        app: flext-ldap-app
    spec:
      containers:
        - name: app
          image: flext-ldap-app:latest
          ports:
            - containerPort: 8000
          env:
            - name: FLEXT_LDAP_HOST
              valueFrom:
                secretKeyRef:
                  name: ldap-config
                  key: host
            - name: FLEXT_LDAP_BIND_DN
              valueFrom:
                secretKeyRef:
                  name: ldap-config
                  key: bind_dn
            - name: FLEXT_LDAP_BIND_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: ldap-config
                  key: bind_password
            - name: FLEXT_LDAP_BASE_DN
              valueFrom:
                configMapKeyRef:
                  name: ldap-config
                  key: base_dn
          livenessProbe:
            httpGet:
              path: /health
              port: 8000
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /ready
              port: 8000
            initialDelaySeconds: 5
            periodSeconds: 5
          resources:
            requests:
              memory: "256Mi"
              cpu: "250m"
            limits:
              memory: "512Mi"
              cpu: "500m"

---
apiVersion: v1
kind: Secret
metadata:
  name: ldap-config
type: Opaque
stringData:
  host: "ldap.example.com"
  bind_dn: "cn=service,dc=example,dc=com"
  bind_password: "service-password"

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: ldap-config
data:
  base_dn: "dc=example,dc=com"
  port: "636"
  use_ssl: "true"
```

---

## FlextLdif Integration

### Entry Format Conversion

FLEXT-LDAP uses FlextLdif for universal LDIF entry handling with automatic server quirks detection:

```python
from flext_ldap.entry_adapter import FlextLdapEntryAdapter
from flext_ldif import FlextLdifModels
import ldap3

adapter = FlextLdapEntryAdapter()

# Convert ldap3 entries to FlextLdif format
connection = ldap3.Connection(
    ldap3.Server('ldap://server:389'),
    user='cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com',
    password='password',
    auto_bind=True
)

connection.search('ou=users,dc=example,dc=com', '(objectClass=person)')

# Convert search results to FlextLdif
flextldif_entries = []
for ldap3_entry in connection.entries:
    result = adapter.ldap3_to_ldif_entry(ldap3_entry)
    if result.is_success:
        ldif_entry = result.unwrap()
        flextldif_entries.append(ldif_entry)
        print(f"DN: {ldif_entry.dn}")
        print(f"Attributes: {ldif_entry.attributes.attributes}")
```

### LDIF File Processing

Process LDIF files with FlextLdif integration:

```python
from flext_ldap.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.servers import OpenLDAP2Operations

def process_ldif_file():
    """Process LDIF file and import to LDAP server."""
    adapter = FlextLdapEntryAdapter()
    ops = OpenLDAP2Operations()

    # Load LDIF file
    result = adapter.convert_ldif_file_to_entries('users.ldif')
    if result.is_failure:
        print(f"Failed to load LDIF: {result.error}")
        return

    entries = result.unwrap()
    print(f"Loaded {len(entries)} entries from LDIF")

    # Connect to LDAP server
    connection = ldap3.Connection(
        ldap3.Server('ldap://server:389'),
        user='cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com',
        password='password',
        auto_bind=True
    )

    # Import entries
    for entry in entries:
        add_result = ops.add_entry(connection, entry)
        if add_result.is_success:
            print(f"Added: {entry.dn}")
        else:
            print(f"Failed to add {entry.dn}: {add_result.error}")

run(process_ldif_file())
```

### Export to LDIF

Export LDAP entries to LDIF format:

```python
from flext_ldap.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.servers import OpenLDAP2Operations
import ldap3

def export_to_ldif():
    """Export LDAP entries to LDIF file."""
    adapter = FlextLdapEntryAdapter()
    ops = OpenLDAP2Operations()

    # Connect and search
    connection = ldap3.Connection(
        ldap3.Server('ldap://server:389'),
        user='cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com',
        password='password',
        auto_bind=True
    )

    # Paged search for large result sets
    search_result = ops.search_with_paging(
        connection,
        base_dn='ou=users,dc=example,dc=com',
        search_filter='(objectClass=person)',
        page_size=100
    )

    if search_result.is_success:
        entries = search_result.unwrap()
        print(f"Found {len(entries)} entries")

        # Write to LDIF file
        write_result = adapter.write_entries_to_ldif_file(
            entries,
            'export.ldif'
        )

        if write_result.is_success:
            print("Export completed successfully")
        else:
            print(f"Export failed: {write_result.error}")

run(export_to_ldif())
```

### Server Quirks Detection

Use FlextLdif quirks system for automatic server detection:

```python
from flext_ldap.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.quirks_integration import FlextLdapQuirksAdapter
from flext_ldap.servers import (
    OpenLDAP2Operations, OracleOIDOperations, OracleOUDOperations
)
import ldap3

def detect_and_configure():
    """Detect server type and configure operations accordingly."""
    connection = ldap3.Connection(
        ldap3.Server('ldap://server:389'),
        user='cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com',
        password='password',
        auto_bind=True
    )

    adapter = FlextLdapEntryAdapter()
    quirks = FlextLdapQuirksAdapter()

    # Get root DSE and schema entries
    connection.search('', '(objectClass=*)', search_scope='BASE', attributes=['*', '+'])
    connection.search('cn=subschema', '(objectClass=*)', attributes=['*'])

    # Convert to FlextLdif
    entries = []
    for ldap3_entry in connection.entries:
        result = adapter.ldap3_to_ldif_entry(ldap3_entry)
        if result.is_success:
            entries.append(result.unwrap())

    # Detect server type
    server_type_result = quirks.detect_server_type_from_entries(entries)
    if server_type_result.is_success:
        server_type = server_type_result.unwrap()
        print(f"Detected server: {server_type}")

        # Get server-specific configuration
        acl_attr_result = quirks.get_acl_attribute_name(server_type)
        schema_dn_result = quirks.get_schema_subentry(server_type)
        max_page_size_result = quirks.get_max_page_size(server_type)

        if all(r.is_success for r in [acl_attr_result, schema_dn_result, max_page_size_result]):
            print(f"ACL attribute: {acl_attr_result.unwrap()}")
            print(f"Schema DN: {schema_dn_result.unwrap()}")
            print(f"Max page size: {max_page_size_result.unwrap()}")

        # Select appropriate operations
        if server_type == "openldap2":
            ops = OpenLDAP2Operations()
        elif server_type == "oid":
            ops = OracleOIDOperations()
        elif server_type == "oud":
            ops = OracleOUDOperations()
        else:
            from flext_ldap.servers import GenericServerOperations
            ops = GenericServerOperations()

        return ops

run(detect_and_configure())
```

### Universal LDAP Processor

Complete example combining FlextLdif with server operations:

```python
from flext_ldap.entry_adapter import FlextLdapEntryAdapter
from flext_ldap.quirks_integration import FlextLdapQuirksAdapter
from flext_ldap.servers import (
    OpenLDAP2Operations, OracleOIDOperations, OracleOUDOperations, GenericServerOperations
)
from flext_ldif import FlextLdifModels
import ldap3

class UniversalLdapProcessor:
    """Universal LDAP processor with FlextLdif integration."""

    def __init__(self, host: str, bind_dn: str, bind_password: str):
        self.host = host
        self.bind_dn = bind_dn
        self.bind_password = bind_password
        self.adapter = FlextLdapEntryAdapter()
        self.quirks = FlextLdapQuirksAdapter()
        self.ops = None
        self.connection = None

    def connect(self):
        """Connect and detect server type."""
        self.connection = ldap3.Connection(
            ldap3.Server(self.host),
            user=self.bind_dn,
            password=self.bind_password,
            auto_bind=True
        )

        # Detect server type
        self.connection.search('', '(objectClass=*)', search_scope='BASE', attributes=['*'])

        entries = []
        for ldap3_entry in self.connection.entries:
            result = self.adapter.ldap3_to_ldif_entry(ldap3_entry)
            if result.is_success:
                entries.append(result.unwrap())

        server_type_result = self.quirks.detect_server_type_from_entries(entries)
        if server_type_result.is_success:
            server_type = server_type_result.unwrap()

            # Select operations
            if server_type == "openldap2":
                self.ops = OpenLDAP2Operations()
            elif server_type == "oid":
                self.ops = OracleOIDOperations()
            elif server_type == "oud":
                self.ops = OracleOUDOperations()
            else:
                self.ops = GenericServerOperations()

            return server_type

    def search_and_export(self, base_dn: str, filter_str: str, output_file: str):
        """Search LDAP and export to LDIF."""
        if not self.ops:
            raise Exception("Not connected")

        # Paged search
        search_result = self.ops.search_with_paging(
            self.connection,
            base_dn=base_dn,
            search_filter=filter_str,
            page_size=100
        )

        if search_result.is_failure:
            raise Exception(f"Search failed: {search_result.error}")

        entries = search_result.unwrap()

        # Write to LDIF
        write_result = self.adapter.write_entries_to_ldif_file(
            entries,
            output_file
        )

        if write_result.is_failure:
            raise Exception(f"Export failed: {write_result.error}")

        return len(entries)

    def import_ldif(self, ldif_file: str, base_dn: str):
        """Import LDIF file to LDAP."""
        if not self.ops:
            raise Exception("Not connected")

        # Load LDIF
        load_result = self.adapter.convert_ldif_file_to_entries(ldif_file)
        if load_result.is_failure:
            raise Exception(f"Load failed: {load_result.error}")

        entries = load_result.unwrap()

        # Import entries
        success_count = 0
        for entry in entries:
            add_result = self.ops.add_entry(self.connection, entry)
            if add_result.is_success:
                success_count += 1

        return success_count

# Usage
def main():
    processor = UniversalLdapProcessor(
        host='ldap://server:389',
        bind_dn='cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com',
        bind_password='password'
    )

    server_type = processor.connect()
    print(f"Connected to {server_type} server")

    # Export to LDIF
    count = processor.search_and_export(
        base_dn='ou=users,dc=example,dc=com',
        filter_str='(objectClass=person)',
        output_file='users_export.ldif'
    )
    print(f"Exported {count} entries")

    # Import from LDIF
    imported = processor.import_ldif(
        ldif_file='users_import.ldif',
        base_dn='ou=users,dc=example,dc=com'
    )
    print(f"Imported {imported} entries")

run(main())
```

---

## Monitoring and Observability

### Prometheus Metrics

```python
from prometheus_client import Counter, Histogram, start_http_server
from flext_ldap import get_flext_ldap_api
import time

# Metrics
ldap_operations_total = Counter(
    'ldap_operations_total',
    'Total LDAP operations',
    ['operation', 'status']
)

ldap_operation_duration = Histogram(
    'ldap_operation_duration_seconds',
    'LDAP operation duration',
    ['operation']
)

class MetricsWrapper:
    """Wrapper to add metrics to LDAP operations."""

    def __init__(self):
        self._ldap_api = get_flext_ldap_api()

    def authenticate_user_with_metrics(self, username: str, password: str):
        """Authenticate user with metrics collection."""
        start_time = time.time()

        try:
            result = self._ldap_api.authenticate_user(username, password)

            status = 'success' if result.is_success else 'failure'
            ldap_operations_total.labels(operation='authenticate', status=status).inc()

            return result
        finally:
            duration = time.time() - start_time
            ldap_operation_duration.labels(operation='authenticate').observe(duration)

# Start metrics server
start_http_server(8001)
```

### Health Check Endpoints

```python
from fastapi import FastAPI
from flext_ldap import get_flext_ldap_api

app = FastAPI()

@app.get("/health")
def health_check():
    """Basic health check endpoint."""
    return {"status": "healthy", "service": "flext-ldap-app"}

@app.get("/ready")
def readiness_check():
    """Readiness check with LDAP connectivity."""
    ldap_api = get_flext_ldap_api()

    connection_result = ldap_api.test_connection()

    if connection_result.is_success:
        return {"status": "ready", "ldap": "connected"}
    else:
        return {
            "status": "not ready",
            "ldap": "disconnected",
            "error": connection_result.error
        }, 503
```

---

For more integration examples and patterns, see the [examples/](examples/) directory.

---

**Next:** [Troubleshooting Guide](troubleshooting.md) →

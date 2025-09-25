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

    async def process_user_authentication(self, username: str, password: str) -> FlextResult[dict]:
        """Process authentication using FLEXT + LDAP patterns."""
        self._logger.info("Processing user authentication", extra={"username": username})

        auth_result = await self._ldap_api.authenticate_user(username, password)
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

async def authenticate_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Dependency for LDAP-based token authentication."""
    # Token validation logic here
    return credentials.credentials

@app.post("/auth/login")
async def login(username: str, password: str) -> dict:
    """User login endpoint with LDAP authentication."""
    ldap_api = get_flext_ldap_api()

    auth_result = await ldap_api.authenticate_user(username, password)
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
async def search_users(
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

    result = await ldap_api.search_entries(search_request)
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
async def create_user(
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

    result = await ldap_api.create_user(create_request)
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
import asyncio

class FlextLdapBackend(BaseBackend):
    """Django authentication backend using FLEXT-LDAP."""

    def authenticate(self, request, username=None, password=None, **kwargs):
        """Authenticate user against LDAP directory."""
        if not username or not password:
            return None

        # Run async LDAP authentication
        try:
            ldap_api = get_flext_ldap_api()
            auth_result = asyncio.run(ldap_api.authenticate_user(username, password))

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
        staff_groups = ['cn=admins,ou=groups,dc=example,dc=com']
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
import asyncio

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
        asyncio.run(self._sync_users(options['dry_run']))

    async def _sync_users(self, dry_run: bool):
        """Perform user synchronization."""
        ldap_api = get_flext_ldap_api()

        # Search for all users
        search_request = FlextLdapEntities.SearchRequest(
            base_dn="ou=users,dc=example,dc=com",
            filter_str="(objectClass=person)",
            scope="subtree",
            attributes=["uid", "cn", "sn", "givenName", "mail", "memberOf"]
        )

        result = await ldap_api.search_entries(search_request)
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
import asyncio

app = Flask(__name__)

def async_route(f):
    """Decorator to handle async routes in Flask."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
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

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        auth_result = loop.run_until_complete(
            ldap_api.authenticate_user(username, password)
        )
        return auth_result.is_success
    finally:
        loop.close()

@app.route('/api/users/search')
@require_auth
@async_route
async def search_users():
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

    result = await ldap_api.search_entries(search_request)
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
      - FLEXT_LDAP_BIND_DN=cn=admin,dc=example,dc=com
      - FLEXT_LDAP_BIND_PASSWORD=admin
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
      - LDAP_ADMIN_PASSWORD=admin
    ports:
      - "389:389"
      - "636:636"
    volumes:
      - ldap_data:/var/lib/ldap
      - ldap_config:/etc/ldap/slapd.d

  ldap-admin:
    image: osixia/phpldapadmin:latest
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
    CMD python -c "from flext_ldap import get_flext_ldap_api; import asyncio; asyncio.run(get_flext_ldap_api().test_connection())"

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

    async def authenticate_user_with_metrics(self, username: str, password: str):
        """Authenticate user with metrics collection."""
        start_time = time.time()

        try:
            result = await self._ldap_api.authenticate_user(username, password)

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
async def health_check():
    """Basic health check endpoint."""
    return {"status": "healthy", "service": "flext-ldap-app"}

@app.get("/ready")
async def readiness_check():
    """Readiness check with LDAP connectivity."""
    ldap_api = get_flext_ldap_api()

    connection_result = await ldap_api.test_connection()

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

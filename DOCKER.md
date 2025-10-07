# flext-ldap Docker Infrastructure

**ZERO TOLERANCE TESTING**: Real LDAP server for maximum functional validation

## Quick Start

```bash
# Start LDAP server
make ldap-start

# Check server health
make ldap-health

# View server logs
make ldap-logs

# Stop LDAP server
make ldap-stop

# Clean all data (full reset)
make ldap-clean
```

## Server Configuration

- **Container Name**: `flext-openldap-test`
- **Image**: `osixia/openldap:1.5.0`
- **LDAP Port**: `3390` (non-standard to avoid conflicts)
- **LDAPS Port**: `3636` (SSL/TLS - not used in testing)
- **Domain**: `internal.invalid`
- **Base DN**: `dc=flext,dc=local`
- **Admin DN**: `cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local`
- **Admin Password**: `REDACTED_LDAP_BIND_PASSWORD123`

## Environment Variables (Auto-loaded from .env.minimal)

```bash
FLEXT_LDAP_LDAP_SERVER_URI=ldap://localhost
FLEXT_LDAP_LDAP_PORT=3390
FLEXT_LDAP_LDAP_BIND_DN=cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local
FLEXT_LDAP_LDAP_BIND_PASSWORD=REDACTED_LDAP_BIND_PASSWORD123
FLEXT_LDAP_LDAP_BASE_DN=dc=flext,dc=local
```

## Initial Data Structure

The server is pre-loaded with test data from `tests/fixtures/ldap/01-initial-structure.ldif`:

### Organizational Units
- `ou=users,dc=flext,dc=local` - User accounts
- `ou=groups,dc=flext,dc=local` - Group definitions
- `ou=services,dc=flext,dc=local` - Service accounts

### Test Users
- `cn=test.user,ou=users,dc=flext,dc=local` - Standard test user
- `cn=REDACTED_LDAP_BIND_PASSWORD.user,ou=users,dc=flext,dc=local` - Admin test user

### Test Groups
- `cn=developers,ou=groups,dc=flext,dc=local` - Developers group
- `cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=flext,dc=local` - Administrators group

### Service Accounts
- `cn=api-service,ou=services,dc=flext,dc=local` - API service account

## Testing with Real LDAP Server

```bash
# Start server in background
make ldap-start

# Wait for health check
make ldap-health

# Run integration tests
make test-integration

# Run all tests with real LDAP
pytest tests/ --ldap-real

# Stop server when done
make ldap-stop
```

## Manual LDAP Operations

```bash
# Search all users
docker exec flext-openldap-test ldapsearch -x \
  -H ldap://localhost:389 \
  -D "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local" \
  -w "REDACTED_LDAP_BIND_PASSWORD123" \
  -b "ou=users,dc=flext,dc=local"

# Add entry manually
docker exec flext-openldap-test ldapadd -x \
  -H ldap://localhost:389 \
  -D "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local" \
  -w "REDACTED_LDAP_BIND_PASSWORD123" \
  -f /path/to/entry.ldif

# Modify entry
docker exec flext-openldap-test ldapmodify -x \
  -H ldap://localhost:389 \
  -D "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local" \
  -w "REDACTED_LDAP_BIND_PASSWORD123" \
  -f /path/to/modify.ldif

# Delete entry
docker exec flext-openldap-test ldapdelete -x \
  -H ldap://localhost:389 \
  -D "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local" \
  -w "REDACTED_LDAP_BIND_PASSWORD123" \
  "cn=entry.to.delete,ou=users,dc=flext,dc=local"
```

## Health Check

The container includes an automatic health check:

```bash
# Check health status
docker ps | grep flext-openldap-test

# View health check logs
docker inspect flext-openldap-test | grep -A 10 Health

# Manual health check
make ldap-health
```

Health check runs every 10 seconds and verifies LDAP search works.

## Data Persistence

Data is stored in named Docker volumes:

- `flext-ldap-data` - LDAP database files
- `flext-ldap-config` - LDAP configuration

To preserve data across container restarts, the volumes persist automatically. To reset:

```bash
make ldap-clean  # Removes volumes and containers
```

## Troubleshooting

### Server won't start
```bash
# Check if port 3390 is in use
lsof -i :3390

# View container logs
docker logs flext-openldap-test

# Check Docker Compose status
docker-compose ps
```

### Connection refused
```bash
# Verify server is running
make ldap-health

# Check port mapping
docker port flext-openldap-test

# Test direct connection
ldapsearch -x -H ldap://localhost:3390 \
  -D "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local" \
  -w "REDACTED_LDAP_BIND_PASSWORD123" \
  -b "dc=flext,dc=local"
```

### Data not loading
```bash
# Check LDIF fixtures exist
ls -la tests/fixtures/ldap/*.ldif

# View bootstrap logs
docker logs flext-openldap-test | grep -i bootstrap

# Manually load LDIF
docker exec flext-openldap-test ldapadd -x \
  -H ldap://localhost:389 \
  -D "cn=REDACTED_LDAP_BIND_PASSWORD,dc=flext,dc=local" \
  -w "REDACTED_LDAP_BIND_PASSWORD123" \
  -f /container/service/slapd/assets/config/bootstrap/ldif/custom/01-initial-structure.ldif
```

## Network Configuration

The container uses a dedicated bridge network `flext-ldap-network` for isolation.

## Security Notes

**TESTING ONLY**: This setup uses plaintext passwords and is NOT suitable for production.

- No SSL/TLS enabled (LDAP_TLS=false)
- Simple REDACTED_LDAP_BIND_PASSWORD password (REDACTED_LDAP_BIND_PASSWORD123)
- Exposed ports on localhost
- Debug logging enabled

## Integration with CI/CD

```yaml
# GitHub Actions example
services:
  ldap:
    image: osixia/openldap:1.5.0
    env:
      LDAP_DOMAIN: internal.invalid
      LDAP_ADMIN_PASSWORD: REDACTED_LDAP_BIND_PASSWORD123
    ports:
      - 3390:389
```

## Copyright

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

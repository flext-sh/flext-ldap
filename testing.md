# FLEXT-LDAP Testing Plan & Status

<!-- TOC START -->
- [Testing Overview](#testing-overview)
- [Test Environment](#test-environment)
  - [Docker LDAP Test Server](#docker-ldap-test-server)
  - [Test Categories](#test-categories)
- [Current Test Coverage](#current-test-coverage)
- [Test Failure Analysis](#test-failure-analysis)
- [Coverage Targets](#coverage-targets)
- [Next Steps](#next-steps)
- [Current Status Summary](#current-status-summary)
<!-- TOC END -->

## Testing Overview

| Metric | Current value |
| ------ | ------------- |
| Unit tests | 245 passed |
| Unit-test command | `uv run pytest flext-ldap/tests/unit -q --tb=short -o addopts="--cov=flext_ldap --cov-report=term-missing:skip-covered"` |
| `flext_ldap` unit coverage | **74.64%** (1,743 statements, 442 missed) |
| Integration tests | 1 smoke test (`tests/integration/test_smoke.py`) |
| Current failures | 0 unit failures |
| Skipped tests | Integration tests gated by the `docker`/`integration` markers when no LDAP server is available |

> Historical claims of 35% coverage, 1,079 tests, and 51 test files are stale.
> The numbers above reflect the current repository state.

## Test Environment

### Docker LDAP Test Server

**Configuration**:

- **Image**: `osixia/openldap:1.5.0`
- **Port**: 3390 (non-standard to avoid conflicts)
- **Domain**: `internal.invalid`
- **Base DN**: `dc=flext,dc=local`
- **Container Name**: `flext-ldap-test-server`

**Management Commands**:

```bash
# Start test server
make ldap-test-server

# Stop test server
make ldap-test-server-stop

# Manual LDAP operations
docker exec -it flext-ldap-test-server ldapsearch \
  -x -H ldap://localhost:389 \
  -D "cn=admin,dc=flext,dc=local" \
  -w "adminpassword" \
  -b "dc=flext,dc=local"
```

### Test Categories

#### 1. Unit Tests (`tests/unit/`)

**Purpose**: Individual component testing without external dependencies.
**Current Status**: 14 test files, primary test category.
**Coverage Focus**: Domain logic, value objects, entities, adapter behaviour.

#### 2. Integration Tests (`tests/integration/`)

**Purpose**: Real LDAP server testing with Docker container.
**Current Status**: 1 smoke test file, gated by `docker`/`integration` markers.
**Coverage Focus**: End-to-end LDAP operations, server-specific behaviours.

## Current Test Coverage

Coverage measured for `flext_ldap` only, from the unit-test run:

| Module | Statements | Missed | Coverage | Status |
| ------ | ---------- | ------ | -------- | ------ |
| `base.py` | 25 | 1 | 96.00% | ✅ |
| `utilities.py` | 289 | 12 | 95.85% | ✅ |
| `_models/ldap.py` | 160 | 17 | 89.38% | ✅ |
| `services/api_runtime.py` | 12 | 2 | 83.33% | ✅ |
| `services/sync.py` | 117 | 30 | 74.36% | ✅ |
| `services/detection.py` | 24 | 7 | 70.83% | ✅ |
| `adapters/ldap3.py` | 86 | 29 | 66.28% | ⚠️ |
| `adapters/_ldap3/connection_manager.py` | 29 | 11 | 62.07% | ⚠️ |
| `services/connection.py` | 44 | 21 | 52.27% | ⚠️ |
| `services/operations.py` | 204 | 97 | 52.45% | ⚠️ |
| `adapters/entry.py` | 73 | 40 | 45.21% | ⚠️ |
| `adapters/_ldap3/operation_executor.py` | 39 | 22 | 43.59% | 🚧 |
| `adapters/_ldap3/wrappers.py` | 59 | 36 | 38.98% | 🚧 |
| `adapters/_ldap3/result_converter.py` | 30 | 20 | 33.33% | 🚧 |
| `adapters/_ldap3/search_executor.py` | 33 | 24 | 27.27% | 🚧 |
| `adapters/_ldap3/result_extract.py` | 92 | 73 | 20.65% | 🚧 |

Full module coverage (constants, models, protocols, settings, typings) is 100% and omitted from the table.

## Test Failure Analysis

### Current Failures

No unit-test failures. Integration tests are skipped unless the Docker LDAP server is running.

### Skipped Tests

Integration tests under `tests/integration/` are gated by `@pytest.mark.integration` / `@pytest.mark.docker`. They run only when the LDAP test container is available.

## Coverage Targets

Targets are configured in `pyproject.toml`:

- `[tool.coverage.report] fail_under = 15` — enforced baseline.
- **Current `flext_ldap` unit coverage**: 74.64%.
- **Next target**: keep unit coverage above 70% while closing gaps in `adapters/_ldap3/*` and `services/operations.py`.

## Next Steps

Priority order, derived from the lowest-coverage modules:

1. `adapters/_ldap3/result_extract.py` (20.65%) — add unit tests for result parsing edge cases.
2. `adapters/_ldap3/search_executor.py` (27.27%) — add tests for search execution branches.
3. `adapters/_ldap3/result_converter.py` (33.33%) — add tests for LDAP result conversion.
4. `adapters/_ldap3/wrappers.py` (38.98%) — add tests for ldap3 wrapper helpers.
5. `adapters/entry.py` (45.21%) and `services/operations.py` (52.45%) — extend existing unit tests for error paths.

## Current Status Summary

- **Coverage**: 74.64% unit coverage for `flext_ldap`.
- **Tests**: 245 unit tests passing; integration tests gated by Docker.
- **Failures**: 0 unit failures.
- **Priority gaps**: `adapters/_ldap3/result_extract.py`, `search_executor.py`, `result_converter.py`, `wrappers.py`, plus `services/operations.py`.
- **Blocking issues**: None for unit tests; integration tests require `make ldap-test-server`.

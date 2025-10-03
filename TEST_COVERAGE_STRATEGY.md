# flext-ldap Test Coverage Improvement Strategy

**Date**: 2025-10-01
**Current Coverage**: 28% (measured)
**Target Coverage**: 75% minimum
**Gap**: 47 percentage points

---

## Executive Summary

Strategic plan to improve test coverage from **28% to 75%** through **focused, evidence-based test development** targeting high-impact modules.

### Coverage Improvement Potential by Module

| Module                    | Lines | Current | Target | Gain       | Priority    | Complexity                     |
| ------------------------- | ----- | ------- | ------ | ---------- | ----------- | ------------------------------ |
| **clients.py**            | 1,095 | 7%      | 75%    | **+18.5%** | 🔴 CRITICAL | HIGH (needs Docker LDAP)       |
| **models.py**             | 1,106 | 38%     | 90%    | **+13.0%** | 🔴 HIGH     | MEDIUM (Pydantic models)       |
| **api.py**                | 330   | 27%     | 85%    | **+5.5%**  | 🟠 HIGH     | MEDIUM (facade methods)        |
| **acl/parsers.py**        | 283   | 15%     | 80%    | **+4.2%**  | 🟠 HIGH     | HIGH (complex parsing)         |
| **utilities.py**          | 237   | 26%     | 90%    | **+3.5%**  | 🟡 MEDIUM   | LOW (pure functions)           |
| **validations.py**        | 121   | 16%     | 95%    | **+2.2%**  | 🟡 MEDIUM   | LOW (validation logic)         |
| **exceptions.py**         | 193   | 36%     | 85%    | **+2.1%**  | 🟡 MEDIUM   | LOW (exception classes)        |
| **entry_adapter.py**      | 190   | 35%     | 85%    | **+2.2%**  | 🟡 MEDIUM   | MEDIUM (ldap3 ↔ FlextLdif)    |
| **quirks_integration.py** | 109   | 18%     | 85%    | **+1.7%**  | 🟡 MEDIUM   | MEDIUM (FlextLdif integration) |
| **config.py**             | 176   | 46%     | 85%    | **+1.6%**  | 🟢 LOW      | LOW (configuration)            |

**Total Potential**: ~54% gain available from these 10 modules
**To Reach 75%**: Need ~47% gain (achievable)

---

## Phase 1: Quick Wins (Low-Hanging Fruit) - Target: +15%

**Focus**: Modules with LOW complexity, NO external dependencies

### 1.1 Validations.py (121 lines, 16% → 95%) - **+2.2%**

**Effort**: LOW | **Complexity**: LOW | **Time**: 2-3 hours

**What to Test**:

- All 13 validation methods (pure validation logic)
- FlextResult success and failure cases
- Edge cases (empty strings, None values, invalid formats)
- LDAP-specific validation rules

**Test Strategy**:

```python
# Example test structure
def test_validate_dn_success():
    result = FlextLdapValidations.validate_dn("cn=test,dc=example,dc=com")
    assert result.is_success

def test_validate_dn_empty():
    result = FlextLdapValidations.validate_dn("")
    assert result.is_failure
    assert "DN cannot be empty" in result.error
```

**Files to Create/Enhance**:

- `tests/unit/test_validations.py` (enhance existing)

### 1.2 Exceptions.py (193 lines, 36% → 85%) - **+2.1%**

**Effort**: LOW | **Complexity**: LOW | **Time**: 2-3 hours

**What to Test**:

- All exception classes instantiation
- Message formatting
- Error codes
- Inheritance from FlextExceptions

**Test Strategy**:

```python
def test_ldap_connection_error_creation():
    error = FlextLdapConnectionError("Connection failed", server="ldap://test")
    assert "Connection failed" in str(error)
    assert error.server == "ldap://test"
```

**Files to Create/Enhance**:

- `tests/unit/test_exceptions.py` (enhance existing)

### 1.3 Config.py (176 lines, 46% → 85%) - **+1.6%**

**Effort**: LOW | **Complexity**: LOW | **Time**: 2 hours

**What to Test**:

- Configuration loading
- Default values
- Validation
- Environment variable overrides

**Test Strategy**:

```python
def test_config_defaults():
    config = FlextLdapConfig()
    assert config.server == "localhost"
    assert config.port == 389
```

**Files to Create/Enhance**:

- `tests/unit/test_config.py` (enhance existing)

**Phase 1 Total**: ~6% coverage gain, ~7-8 hours effort

---

## Phase 2: Medium Impact (Moderate Complexity) - Target: +20%

**Focus**: Modules with MEDIUM complexity, SOME mocking required

### 2.1 Models.py (1,106 lines, 38% → 90%) - **+13.0%**

**Effort**: MEDIUM | **Complexity**: MEDIUM | **Time**: 8-10 hours

**What to Test**:

- All Pydantic model instantiation
- Validation rules
- Serialization/deserialization
- Model relationships
- Edge cases

**Test Strategy**:

```python
def test_user_model_creation():
    user = FlextLdapModels.User(
        dn="cn=test,dc=example,dc=com",
        uid="test",
        cn="Test User"
    )
    assert user.uid == "test"
    assert user.dn == "cn=test,dc=example,dc=com"

def test_user_model_validation_failure():
    with pytest.raises(ValidationError):
        FlextLdapModels.User(dn="", uid="")  # Empty required fields
```

**Files to Create/Enhance**:

- `tests/unit/test_models.py` (comprehensive rewrite)

### 2.2 API.py (330 lines, 27% → 85%) - **+5.5%**

**Effort**: MEDIUM | **Complexity**: MEDIUM | **Time**: 6-8 hours

**What to Test**:

- All facade methods
- Delegation to client
- FlextResult wrapping
- Error handling
- Integration patterns

**Test Strategy**:

```python
@pytest.fixture
def mock_client():
    return Mock(spec=FlextLdapClient)

def test_api_search_users(mock_client):
    api = FlextLdapAPI(client=mock_client)
    mock_client.search_users.return_value = FlextResult[list].ok([])

    result = api.search_users(base_dn="dc=test")
    assert result.is_success
    mock_client.search_users.assert_called_once()
```

**Files to Create/Enhance**:

- `tests/unit/test_api.py` (significant enhancement)

### 2.3 Utilities.py (237 lines, 26% → 90%) - **+3.5%**

**Effort**: MEDIUM | **Complexity**: LOW | **Time**: 4-5 hours

**What to Test**:

- All utility functions
- Type guards (TypeGuards class)
- Processing functions
- Conversion functions
- Edge cases

**Test Strategy**:

```python
def test_normalize_dn():
    result = FlextLdapUtilities.normalize_dn("CN=Test,DC=Example")
    assert result == "cn=test,dc=example"

def test_is_ldap_dn_valid():
    assert FlextLdapUtilities.is_ldap_dn("cn=test,dc=example") is True
    assert FlextLdapUtilities.is_ldap_dn("invalid") is False
```

**Files to Create/Enhance**:

- `tests/unit/test_utilities.py` (enhance existing - already has 764 lines)

**Phase 2 Total**: ~22% coverage gain, ~18-23 hours effort

---

## Phase 3: High Impact (High Complexity) - Target: +25%

**Focus**: Modules requiring Docker LDAP server or complex mocking

### 3.1 Clients.py (1,095 lines, 7% → 75%) - **+18.5%**

**Effort**: HIGH | **Complexity**: HIGH | **Time**: 20-25 hours

**Challenges**:

- Requires Docker LDAP server
- 83 methods to test
- Integration with ldap3
- operations
- Connection management

**Test Strategy**:

```python
@pytest.fixture
def ldap_server():
    """Docker LDAP server fixture."""
    # Use existing conftest.py fixtures
    return real_ldap_server()

def test_connect_success(ldap_server):
    client = FlextLdapClient(config=test_config)
    result = client.connect()
    assert result.is_success

def test_authenticate_user(ldap_server):
    client = FlextLdapClient(config=test_config)
    client.connect()
    result = client.authenticate_user("testuser", "password")
    assert result.is_success
```

**Files to Create/Enhance**:

- `tests/unit/test_clients.py` (already 765 lines - enhance significantly)
- `tests/integration/test_clients_integration.py` (new - Docker tests)

### 3.2 ACL/Parsers.py (283 lines, 15% → 80%) - **+4.2%**

**Effort**: HIGH | **Complexity**: HIGH | **Time**: 8-10 hours

**Challenges**:

- Complex ACL parsing logic
- Multiple ACL formats (OpenLDAP, OID, OUD, AD)
- Edge cases and malformed input

**Test Strategy**:

```python
def test_parse_openldap_acl():
    acl = "to * by self write by anonymous auth"
    result = FlextLdapAclParsers.parse_openldap(acl)
    assert result.is_success
    assert result.unwrap()["to"] == "*"

def test_parse_malformed_acl():
    acl = "invalid acl string"
    result = FlextLdapAclParsers.parse_openldap(acl)
    assert result.is_failure
```

**Files to Create/Enhance**:

- `tests/unit/test_acl_parsers.py` (new)

### 3.3 Entry Adapter (190 lines, 35% → 85%) - **+2.2%**

**Effort**: MEDIUM | **Complexity**: MEDIUM | **Time**: 4-5 hours

**What to Test**:

- ldap3 → FlextLdif conversion
- FlextLdif → ldap3 conversion
- Entry attribute handling
- Edge cases

**Test Strategy**:

```python
def test_ldap3_to_ldif_conversion():
    ldap3_entry = {"dn": "cn=test", "attributes": {"cn": ["test"]}}
    result = adapter.ldap3_to_ldif_entry(ldap3_entry)
    assert result.is_success
    assert isinstance(result.unwrap(), FlextLdifModels.Entry)
```

**Files to Create/Enhance**:

- `tests/unit/test_entry_adapter_universal.py` (enhance existing - already 20 tests)

**Phase 3 Total**: ~25% coverage gain, ~32-40 hours effort

---

## Implementation Priorities

### Priority 1: Immediate (Next 2-3 days)

**Target**: +6% coverage (28% → 34%)

- validations.py
- exceptions.py
- config.py

**Rationale**: Quick wins, low complexity, no external dependencies

### Priority 2: Short-term (Next 1-2 weeks)

**Target**: +22% coverage (34% → 56%)

- models.py (MASSIVE impact: +13%)
- api.py (+5.5%)
- utilities.py (+3.5%)

**Rationale**: Medium complexity, significant impact, mostly unit tests

### Priority 3: Medium-term (Next 2-4 weeks)

**Target**: +19% coverage (56% → 75%)

- clients.py (CRITICAL: +18.5%)
- acl/parsers.py (+4.2%)
- Others to fill gap

**Rationale**: High complexity, requires Docker LDAP, but essential for 75% target

---

## Test Development Standards

### MANDATORY Patterns

1. **Use pytest fixtures** from `tests/conftest.py`
2. **Use FlextResult assertions**:

   ```python
   assert result.is_success
   assert result.is_failure
   assert result.unwrap() == expected_value
   ```

3. **Use parametrize for multiple cases**:

   ```python
   @pytest.mark.parametrize("input,expected", [
       ("valid", True),
       ("invalid", False),
   ])
   def test_validation(input, expected):
       result = validate(input)
       assert result == expected
   ```

4. **Mock external dependencies** (ldap3, FlextLdif when needed)
5. **Test FlextResult error cases**:

   ```python
   result = function_that_fails()
   assert result.is_failure
   assert "expected error" in result.error
   ```

### Test Structure

```python
# tests/unit/test_[module].py
from __future__ import annotations

import pytest
from flext_core import FlextResult
from flext_ldap.[module] import Flext[Module]

class Test[Module]:
    """Test suite for [Module]."""

    def test_[operation]_success(self):
        """Test successful [operation]."""
        result = Flext[Module].[operation](valid_input)
        assert result.is_success
        assert result.unwrap() == expected_output

    def test_[operation]_failure(self):
        """Test [operation] with invalid input."""
        result = Flext[Module].[operation](invalid_input)
        assert result.is_failure
        assert "error message" in result.error

    @pytest.mark.parametrize("input,expected", [
        # Multiple test cases
    ])
    def test_[operation]_edge_cases(self, input, expected):
        """Test [operation] edge cases."""
        result = Flext[Module].[operation](input)
        assert result == expected
```

---

## Coverage Measurement Commands

```bash
# Quick check - integration tests only (fast)
poetry run python -m pytest tests/integration/test_universal_ldap_integration.py \
  --cov=src/flext_ldap --cov-report=term-missing --tb=no -q

# Full unit tests (may timeout for clients.py)
poetry run python -m pytest tests/unit/ \
  --cov=src/flext_ldap --cov-report=term-missing \
  --ignore=tests/unit/test_models.py --tb=no -q

# Specific module coverage
poetry run python -m pytest tests/unit/test_[module].py \
  --cov=src/flext_ldap/[module].py --cov-report=term-missing -v

# Target: Reach 75% minimum
poetry run python -m pytest tests/ \
  --cov=src/flext_ldap --cov-report=term-missing \
  --cov-fail-under=75
```

---

## Expected Timeline

| Phase                   | Target      | Effort          | Timeline      |
| ----------------------- | ----------- | --------------- | ------------- |
| Phase 1 (Quick Wins)    | +6% (→34%)  | 7-8 hours       | 2-3 days      |
| Phase 2 (Medium Impact) | +22% (→56%) | 18-23 hours     | 1-2 weeks     |
| Phase 3 (High Impact)   | +19% (→75%) | 32-40 hours     | 2-4 weeks     |
| **Total**               | **+47%**    | **57-71 hours** | **3-6 weeks** |

**Note**: Timeline assumes focused, dedicated test development work. Actual time may vary based on:

- Docker LDAP server setup issues
- Complexity of clients.py integration tests
- Unexpected edge cases requiring additional test cases

---

## Risk Assessment

### HIGH RISK

- **clients.py timeout issues**: Tests take >60s due to Docker LDAP server
  - **Mitigation**: Separate unit tests (mocked) from integration tests (Docker)
  - **Mitigation**: Optimize Docker container management in conftest.py

### MEDIUM RISK

- **models.py Pydantic complexity**: 1,106 lines of complex domain models
  - **Mitigation**: Break into smaller test classes by model type
  - **Mitigation**: Focus on critical models first (User, Group, SearchRequest)

### LOW RISK

- **Validation/Config/Exceptions**: Low complexity, straightforward tests
  - **Mitigation**: None needed - quick wins expected

---

## Success Criteria

**Minimum (75% coverage)**:

- ✅ Phase 1 complete: validations, exceptions, config
- ✅ Phase 2 complete: models, api, utilities
- ✅ Phase 3 partial: clients.py at least 50% (from 7%)

**Ideal (85% coverage)**:

- ✅ All phases complete
- ✅ clients.py at 75%+
- ✅ All server operations modules improved

**Excellence (90%+ coverage)**:

- ✅ clients.py at 85%+
- ✅ ACL parsers fully tested
- ✅ All edge cases covered

---

## Next Steps (Immediate Actions)

1. **Start with Phase 1**: validations.py tests (2-3 hours)
2. **Measure progress**: Run coverage after each module
3. **Track in todo**: Update progress tracking
4. **Document blockers**: Note any issues encountered
5. **Iterate**: Continue through phases based on results

---

**Created**: 2025-10-01
**Status**: READY FOR IMPLEMENTATION
**Priority**: HIGH (required for 1.0.0 release)
**Evidence**: Based on measured 28% coverage and detailed module analysis

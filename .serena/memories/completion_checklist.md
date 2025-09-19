# FLEXT Task Completion Checklist

## Mandatory Quality Gates (Stop on Failure)

1. **Ruff Check**: `ruff check .` - Zero violations allowed
2. **MyPy Check**: `mypy .` - Zero type errors in strict mode
3. **Pyright Check**: `pyright` - Secondary type validation
4. **Pytest Coverage**: 100% target, 75% minimum for flext-core

## After Each File Edit

```bash
# Immediate validation after changes
ruff check <changed_paths>  # Fix before continuing
```

## Before object Commit

```bash
# Complete validation pipeline
make validate

# Or one-liner gate check
ruff check . && mypy . && pyright && \
pytest -q --maxfail=1 --cov=src --cov=examples --cov=tests --cov=. \
       --cov-report=term-missing:skip-covered \
       --cov-fail-under=100
```

## Refactoring Requirements

- [ ] Replace legacy access with direct flext-core API
- [ ] Unify to single-class-per-module
- [ ] Use Pydantic models, delete ad-hoc validation
- [ ] Update examples/tests to current flext-core API
- [ ] Fix imports/types at origin, no suppression
- [ ] Eliminate TODOs, placeholders, try/except pass
- [ ] Use FlextConstants, never duplicate constants
- [ ] Tests MUST use flext_tests, NO mocks

## Documentation Requirements

- [ ] Professional English throughout
- [ ] Google style docstrings for all public APIs
- [ ] Complete examples for complex functions
- [ ] Update third-party calls to latest signatures

## Final Validation

- [ ] Zero ruff violations
- [ ] Zero mypy/pyright errors in src/
- [ ] 100% test coverage (75% minimum for core)
- [ ] All tests passing
- [ ] No # type: ignore without specific codes
- [ ] No object types
- [ ] No fallback mechanisms
- [ ] Single class per module achieved

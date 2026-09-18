# from flext-ldap_docs/development/README.md:205
from __future__ import annotations

from pydantic import PositiveInt


class Config(m.BaseModel):
    """Use Pydantic v2 native types."""

    timeout: PositiveInt  # Built-in validation
    host: str```
## Git Workflow

### Branch Naming

- `feature/description` - New features
- `fix/description` - Bug fixes
- `refactor/description` - Refactoring
- `docs/description` - Documentation
- `test/description` - Test improvements

### Commit Messages

Follow Conventional Commits:```
feat: add new LDAP operation
fix: resolve connection timeout issue
refactor: simplify authentication logic
docs: update API documentation
test: add integration tests for OID```
## Pull Request Checklist

- [ ] Code follows FLEXT patterns
- [ ] All quality gates pass (`make val`)
- [ ] Tests pass (`make test`)
- [ ] Test coverage maintained (75%+)
- [ ] Documentation updated
- [ ] CHANGELOG updated (if applicable)
- [ ] No breaking changes (or documented)
- [ ] Self-review completed

## Getting Help

### Resources

- **Architecture**: docs/architecture/
- **API Reference**: docs/api/
- **Refactoring Docs**: docs/refactoring/

### Communication

- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions
- **Security**: Private maintainer contact

## Best Practices

### DO ✅

- Use r[T] for all operations
- Complete type annotations
- Follow Clean Architecture
- Write tests for new features
- Document public APIs
- Run `make val` before commits

### DON'T ❌

- Use exceptions for business logic
- Duplicate flext-core functionality
- Skip quality gates
- Commit without tests
- Break layer boundaries
- Use `Any` types

## Related Documentation

- Architecture - System architecture
- API Reference - Complete API docs
- Migration Guide - v0.9.0 → v0.12.0-dev

______________________________________________________________________

**Last Updated**: 2025-01-24
**Maintainer**: FLEXT Team

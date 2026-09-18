# from flext-ldap_docs/api/README.md:126
result = api.search_entries(request)

# Success path
if result.success:
    entries = result.unwrap()

# Failure path
if result.failure:
    error = result.error```
## Related Documentation

- Architecture - Architecture patterns
- Development - Contributing guidelines
- Migration Guide - v0.9.0 → v0.12.0-dev

______________________________________________________________________

**Last Updated**: 2025-01-24
**API Version**: v0.12.0-dev

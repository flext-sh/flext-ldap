# Architecture Documentation

**Version**: 1.0
**Date**: 2025-01-24
**Target Release**: v0.10.0

## Overview

This directory contains comprehensive architecture documentation for flext-ldap, covering the Clean Architecture implementation, module patterns, server-specific operations, and design principles.

## Table of Contents

### Core Architecture

1. **[Clean Architecture](clean-architecture.md)** - Layer separation and dependency rules
2. **[Module Patterns](module-patterns.md)** - Consistent FlextXxx namespace patterns
3. **[Dependency Flow](dependency-flow.md)** - Module dependencies and integration points

### Implementation Details

4. **[Server Operations](server-operations.md)** - Server-specific architecture
5. **[Entry Adapter](entry-adapter.md)** - ldap3 ↔ flext-ldif conversion pattern
6. **[ACL Architecture](acl-architecture.md)** - Server-specific ACL handling

### Design Principles

7. **[Railway-Oriented Programming](railway-programming.md)** - FlextResult[T] pattern
8. **[Type Safety](type-safety.md)** - Python 3.13+ strict typing
9. **[Zero Duplication](zero-duplication.md)** - flext-core integration

## Quick Reference

### Architecture Layers

```
Application Layer → Domain Layer → Infrastructure Layer → Protocol Layer
     ↓                  ↓                ↓                    ↓
   FlextLdap    FlextLdapModels    ServerOperations        ldap3
```

### Module Structure (v0.10.0)

**12 Root Modules**:
- api.py, services.py, handlers.py
- clients.py (Authentication, Search)
- models.py (Domain, Validations)
- schema.py (Sync)
- acl.py (Manager, Parsers, Converters)
- entry_adapter.py, quirks_integration.py
- repositories.py, config.py, utilities.py

**1 Subdirectory**:
- servers/ - Server-specific implementations

## Related Documentation

- [Refactoring Plan](../refactoring/REFACTORING_PLAN.md)
- [Architecture Changes](../refactoring/ARCHITECTURE_CHANGES.md)
- [API Reference](../api/)
- [Development Guides](../development/)

---

**Last Updated**: 2025-01-24

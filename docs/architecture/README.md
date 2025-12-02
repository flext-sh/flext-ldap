# Architecture Documentation

**Version**: 1.1  
**Date**: 2025-03-15  
**Target Release**: v0.11.0

## Overview

This directory houses the living architecture documentation for flext-ldap. The
current codebase centers on a lightweight service layer that orchestrates
`ldap3` operations and `flext-ldif` parsing through a small set of composable
services and adapters. Documentation here reflects the runtime architecture
shipped in the source tree rather than legacy server-specific stacks.

## Table of Contents

### Core Architecture

1. **[C4: System Context](c4-system-context.md)** - External dependencies and boundaries
2. **[C4: Containers](c4-containers.md)** - Major runtime blocks and their contracts
3. **[C4: Components](c4-components.md)** - Service and adapter composition
4. **[C4: Code](c4-code.md)** - Pointers to source files and entry points

### Implementation Details

5. **[Service Layer](service-layer.md)** - Connection, operations, detection, and sync services
6. **[Adapters](adapters.md)** - How ldap3 integration is wrapped in flext services

### Design Principles

7. **[arc42 Views](arc42-03-system-scope-system-scope-and-context.md)** - System scope and context
8. **[Quality Requirements](arc42-10-quality-quality-requirements.md)** - Cross-cutting quality criteria
9. **[Risks and Decisions](arc42-09-decisions-architecture-decisions.md)** - Notable ADRs and open risks

## Quick Reference

### Architecture Layers

```
API Facade → Service Layer → Adapter Layer → Protocol + Models
   FlextLdap     Connection/Ops     Ldap3Adapter       ldap3 / flext-ldif
```

### Module Structure (v0.11.0)

**Root Modules**:

- `api.py` (FlextLdap facade)
- `config.py`, `constants.py`, `models.py`, `protocols.py`, `typings.py`
- `utilities.py` and `base.py` for shared helpers

**Service Packages**:

- `services/connection.py` – connection lifecycle and server detection integration
- `services/operations.py` – CRUD, search, and batch upsert operations
- `services/sync.py` – LDIF-driven synchronization utilities
- `services/detection.py` – runtime server-type detection from rootDSE

**Adapters**:

- `adapters/ldap3.py` – typed wrapper around ldap3 connections and operations
- `adapters/entry.py` – normalization between ldap3 entries and flext-ldif models

## Related Documentation

- [API Reference](../api/)
- [Development Guides](../development/)
- [Maintenance](../maintenance/)

---

**Last Updated**: 2025-03-15

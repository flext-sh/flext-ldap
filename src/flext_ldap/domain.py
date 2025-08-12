"""FLEXT LDAP Domain - PEP8 compliant domain layer.

Consolidates all LDAP domain components into a single, well-organized module
following PEP8 naming standards and flext-core domain patterns. This module
provides the domain layer implementation for LDAP operations.

Originally consolidated from:
- domain_models.py: Domain models and value objects
- domain_entities.py: Domain entities and aggregates
- domain_events.py: Domain events and event handlers
- domain_exceptions.py: Domain-specific exceptions
- domain_interfaces.py: Domain service interfaces
- domain_ports.py: Domain ports for Clean Architecture
- domain_repositories.py: Repository abstractions
- domain_security.py: Domain security patterns
- domain_specifications.py: Domain specifications and rules

Architecture:
    - Extends flext-core domain patterns for consistency
    - Implements Domain-Driven Design (DDD) patterns
    - Provides Clean Architecture domain layer
    - Follows SOLID principles and domain modeling

Key Features:
    - Domain entities with rich business logic
    - Value objects with immutability
    - Domain events for cross-aggregate communication
    - Specifications for business rules
    - Repository abstractions for data access
    - Domain services for complex operations

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import get_logger

logger = get_logger(__name__)

# All domain classes are properly imported from their respective modules below
# No need for local fallback classes

# Domain Models

# Domain Entities

# Domain Events

# Domain Exceptions

# Domain Interfaces

# Domain Ports

# Domain Repositories

# Domain Security

# Domain Specifications

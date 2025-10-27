"""Test support utilities for flext-ldap integration testing.

This package provides utilities for managing test data, fixtures, and
common test patterns for real LDAP operations against Docker containers.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from tests.support.test_data_loader import LdapTestDataLoader

__all__ = [
    "LdapTestDataLoader",
]

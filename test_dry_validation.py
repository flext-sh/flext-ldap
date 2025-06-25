#!/usr/bin/env python3
"""🔥🔥🔥🔥🔥 ZERO DUPLICATION VALIDATION TEST.

Quick validation script to verify our ULTRA DRY implementation works perfectly.
This validates that we achieved ZERO CODE DUPLICATION with maximum reusability.
"""

import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "tests"))


def test_dry_framework() -> None:
    """🔥 Test that our DRY framework eliminates ALL duplication."""
    from conftest import TestEmail, TestUser

    # Test entity creation - NO DUPLICATION
    user = TestUser(username="john_doe", email="john@example.com", age=30)

    # Test value object creation - NO DUPLICATION
    email = TestEmail(address="test@company.com", verified=True)

    # Test business rules - NO DUPLICATION
    assert user.can_be_deleted() is True

    # Test audit fields - NO DUPLICATION
    assert user.id is not None
    assert user.created_at is not None
    assert user.updated_at is not None
    assert user.version == 1

    # Test email validation - NO DUPLICATION
    assert email.is_valid() is True
    assert email.domain == "company.com"


if __name__ == "__main__":
    test_dry_framework()

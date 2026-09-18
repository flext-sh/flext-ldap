# from flext-ldap_docs/troubleshooting.md:640
from __future__ import annotations

from flext_ldap.api import ldap


def handle_errors_properly():
    """Demonstrate proper error handling with r."""
    api = ldap

    # Always check result status
    result = api.authenticate_user("test", "wrong-password")

    if result.success:
        user = result.unwrap()
        print(f"Success: {user.cn}")
    else:
        # Extract error message
        error_msg = result.error
        print(f"Error: {error_msg}")

        # Handle specific error types
        if "Invalid credentials" in error_msg:
            print("Suggestion: Check username and password")
        elif "Connection refused" in error_msg:
            print("Suggestion: Check LDAP server status")
        elif "No such t.JsonValue" in error_msg:
            print("Suggestion: Verify user exists in directory")


run(handle_errors_properly())```
______________________________________________________________________

## Debugging Tools and Techniques

### Enable Debug Logging


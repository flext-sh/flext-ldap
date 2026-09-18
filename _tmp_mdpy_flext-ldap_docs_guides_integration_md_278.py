# from flext-ldap_docs/guides/integration.md:278
from __future__ import annotations

from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User
from flext_ldap.api import ldap


class FlextLdapBackend(BaseBackend):
    """Django authentication backend using FLEXT-LDAP."""

    def authenticate(self, request, username=None, password=None, **kwargs):
        """Authenticate user against LDAP directory."""
        if not username or not password:
            return None

        # Run LDAP authentication
        try:
            ldap_api = ldap
            auth_result = run(ldap_api.authenticate_user(username, password))

            if auth_result.failure:
                return None

            ldap_user = auth_result.unwrap()

            # Get or create Django user
            user, created = User.objects.get_or_create(
                username=ldap_user.uid,
                defaults={
                    "first_name": ldap_user.given_name or "",
                    "last_name": ldap_user.sn or "",
                    "email": ldap_user.mail or "",
                    "is_staff": self._is_staff_user(ldap_user),
                    "is_active": True,
                },
            )

            if not created:
                # Update existing user info
                user.first_name = ldap_user.given_name or user.first_name
                user.last_name = ldap_user.sn or user.last_name
                user.email = ldap_user.mail or user.email
                user.is_staff = self._is_staff_user(ldap_user)
                user.save()

            return user

        except Exception:
            # Log error appropriately
            return None

    def get_user(self, user_id):
        """Get user by ID."""
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def _is_staff_user(self, ldap_user) -> bool:
        """Check if LDAP user should have staff privileges."""
        staff_groups = ["cn=REDACTED_LDAP_BIND_PASSWORDs,ou=groups,dc=example,dc=com"]
        return any(group in ldap_user.member_of for group in staff_groups)


# settings.py
AUTHENTICATION_BACKENDS = [
    "myapp.auth.FlextLdapBackend",
    "django.contrib.auth.backends.ModelBackend",
]```
### Django User Sync Management Command


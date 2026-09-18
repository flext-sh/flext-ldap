# from flext-ldap_docs/guides/integration.md:350
from __future__ import annotations

from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from flext_ldap import FlextLdapEntities
from flext_ldap.api import ldap


class Command(BaseCommand):
    """Sync users from LDAP to Django database."""

    help = "Synchronize users from LDAP directory"

    def add_arguments(self, parser):
        _ = parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be synced without making changes",
        )

    def handle(self, *args, **options):
        """Handle the sync command."""
        run(self._sync_users(options["dry_run"]))

    def _sync_users(self, dry_run: bool):
        """Perform user synchronization."""
        ldap_api = ldap

        # Search for all users
        search_request = FlextLdapEntities.SearchRequest(
            base_dn="ou=users,dc=example,dc=com",
            filter_str="(objectClass=person)",
            scope="subtree",
            attributes=["uid", "cn", "sn", "givenName", "mail", "memberOf"],
        )

        result = ldap_api.search_entries(search_request)
        if result.failure:
            self.stdout.write(self.style.ERROR(f"LDAP search failed: {result.error}"))
            return

        ldap_users = result.unwrap()
        synced_count = 0
        created_count = 0

        for ldap_user in ldap_users:
            try:
                user, created = User.objects.get_or_create(
                    username=ldap_user.uid,
                    defaults={
                        "first_name": ldap_user.given_name or "",
                        "last_name": ldap_user.sn or "",
                        "email": ldap_user.mail or "",
                        "is_active": True,
                    },
                )

                if not dry_run:
                    if created:
                        created_count += 1
                        self.stdout.write(f"Created user: {user.username}")
                    else:
                        # Update existing user
                        updated = False
                        if user.first_name != (ldap_user.given_name or ""):
                            user.first_name = ldap_user.given_name or ""
                            updated = True
                        if user.last_name != (ldap_user.sn or ""):
                            user.last_name = ldap_user.sn or ""
                            updated = True
                        if user.email != (ldap_user.mail or ""):
                            user.email = ldap_user.mail or ""
                            updated = True

                        if updated:
                            user.save()
                            self.stdout.write(f"Updated user: {user.username}")

                synced_count += 1

            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f"Error syncing user {ldap_user.uid}: {e}")
                )

        if dry_run:
            self.stdout.write(
                self.style.SUCCESS(f"Dry run: Would sync {synced_count} users")
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(
                    f"Synced {synced_count} users ({created_count} created)"
                )
            )```
______________________________________________________________________

## Flask Integration

### Flask Application with LDAP Authentication


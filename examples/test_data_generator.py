#!/usr/bin/env python3
"""Test Data Generator - Generate ~1000 LDAP entries for comprehensive validation.

This utility generates diverse LDAP test data covering:
- Multiple organizational layers (OUs)
- Various schemas (person, group, service, computer)
- Realistic attributes and relationships
- Group memberships and hierarchies

Usage:
    python examples/test_data_generator.py --server openldap --output test_data_openldap.ldif
    python examples/test_data_generator.py --server oud --output test_data_oud.ldif

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

# ruff: noqa: S311 - Random used for test data generation only, not cryptographic purposes
from __future__ import annotations

import argparse
import random  # nosec S311 - random used for test data generation only, not security
import sys
from pathlib import Path
from typing import Final

from flext_core import FlextLogger, FlextResult, FlextTypes

from flext_ldap import FlextLdapConstants

logger: FlextLogger = FlextLogger(__name__)

# Test data configuration
DEPARTMENTS: Final[FlextTypes.StringList] = [
    "engineering",
    "marketing",
    "sales",
    "support",
    "contractors",
]
PROJECTS: Final[FlextTypes.StringList] = [
    "alpha",
    "beta",
    "gamma",
    "delta",
    "epsilon",
    "zeta",
    "eta",
    "theta",
    "iota",
    "kappa",
    "lambda",
    "mu",
    "nu",
    "xi",
    "omicron",
    "pi",
    "rho",
    "sigma",
    "tau",
    "upsilon",
]
ROLES: Final[FlextTypes.StringList] = [
    "admin",
    "developer",
    "manager",
    "analyst",
    "architect",
    "designer",
    "tester",
    "operator",
    "auditor",
    "security",
    "backup_admin",
    "network_admin",
    "db_admin",
    "app_admin",
    "sys_admin",
    "devops",
    "sre",
    "consultant",
    "trainer",
    "support_l1",
]

FIRST_NAMES: Final[FlextTypes.StringList] = [
    "John",
    "Jane",
    "Michael",
    "Sarah",
    "David",
    "Emily",
    "Robert",
    "Lisa",
    "James",
    "Mary",
    "William",
    "Patricia",
    "Richard",
    "Jennifer",
    "Charles",
    "Linda",
    "Thomas",
    "Barbara",
    "Christopher",
    "Elizabeth",
]

LAST_NAMES: Final[FlextTypes.StringList] = [
    "Smith",
    "Johnson",
    "Williams",
    "Brown",
    "Jones",
    "Garcia",
    "Miller",
    "Davis",
    "Rodriguez",
    "Martinez",
    "Hernandez",
    "Lopez",
    "Gonzalez",
    "Wilson",
    "Anderson",
    "Thomas",
    "Taylor",
    "Moore",
    "Jackson",
    "Martin",
]

SERVICE_NAMES: Final[FlextTypes.StringList] = [
    "ldap",
    "database",
    "web",
    "api",
    "cache",
    "queue",
    "worker",
    "scheduler",
    "monitor",
    "backup",
    "proxy",
    "gateway",
    "balancer",
    "firewall",
    "vpn",
]

COMPUTER_PREFIXES: Final[FlextTypes.StringList] = [
    "srv",
    "ws",
    "db",
    "web",
    "app",
    "test",
    "dev",
    "prod",
    "staging",
    "backup",
]


class TestDataGenerator:
    """Generate comprehensive LDAP test data with realistic structure."""

    def __init__(self, server_type: str, base_dn: str) -> None:
        """Initialize test data generator.

        Args:
            server_type: Server type (openldap or oud)
            base_dn: Base DN for all entries

        """
        super().__init__()
        self.server_type = server_type
        self.base_dn = base_dn
        self.entries: list[tuple[str, dict[str, str | FlextTypes.StringList]]] = []
        self.user_dns: FlextTypes.StringList = []
        self.group_dns: FlextTypes.StringList = []

    def generate_all_data(
        self,
    ) -> FlextResult[list[tuple[str, dict[str, str | FlextTypes.StringList]]]]:
        """Generate all test data (~1000 entries).

        Returns:
            FlextResult containing list of (dn, attributes) tuples

        """
        logger.info(
            f"Generating test data for {self.server_type} (base_dn={self.base_dn})"
        )

        # Create organizational structure
        self._create_organizational_units()

        # Create users (~500)
        self._create_users()

        # Create groups (~50)
        self._create_groups()

        # Create service accounts (~100)
        self._create_service_accounts()

        # Create computer accounts (~200)
        self._create_computer_accounts()

        # Create additional containers (~150)
        self._create_containers()

        logger.info(f"Generated {len(self.entries)} entries total")
        logger.info(f"  Users: {len(self.user_dns)}")
        logger.info(f"  Groups: {len(self.group_dns)}")
        logger.info(
            f"  Others: {len(self.entries) - len(self.user_dns) - len(self.group_dns)}"
        )

        return FlextResult[list[tuple[str, dict[str, str | FlextTypes.StringList]]]].ok(
            self.entries
        )

    def _create_organizational_units(self) -> None:
        """Create top-level organizational units."""
        logger.info("Creating organizational units...")

        # Main OUs
        main_ous = ["users", "groups", "services", "computers", "containers"]
        for ou in main_ous:
            dn = f"ou={ou},{self.base_dn}"
            attributes: dict[str, str | FlextTypes.StringList] = {
                FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS: [
                    FlextLdapConstants.ObjectClasses.ORGANIZATIONAL_UNIT,
                    FlextLdapConstants.ObjectClasses.TOP,
                ],
                FlextLdapConstants.LdapAttributeNames.OU: ou,
                FlextLdapConstants.LdapAttributeNames.DESCRIPTION: f"{ou.title()} organizational unit",
            }
            self.entries.append((dn, attributes))

        # Department OUs under users
        for dept in DEPARTMENTS:
            dn = f"ou={dept},ou=users,{self.base_dn}"
            attributes = {
                FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS: [
                    FlextLdapConstants.ObjectClasses.ORGANIZATIONAL_UNIT,
                    FlextLdapConstants.ObjectClasses.TOP,
                ],
                FlextLdapConstants.LdapAttributeNames.OU: dept,
                FlextLdapConstants.LdapAttributeNames.DESCRIPTION: f"{dept.title()} department",
            }
            self.entries.append((dn, attributes))

        # Group categories under groups
        for category in ["departments", "projects", "roles"]:
            dn = f"ou={category},ou=groups,{self.base_dn}"
            attributes = {
                FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS: [
                    FlextLdapConstants.ObjectClasses.ORGANIZATIONAL_UNIT,
                    FlextLdapConstants.ObjectClasses.TOP,
                ],
                FlextLdapConstants.LdapAttributeNames.OU: category,
                FlextLdapConstants.LdapAttributeNames.DESCRIPTION: f"{category.title()} groups",
            }
            self.entries.append((dn, attributes))

    def _create_users(self) -> None:
        """Create user entries (~500 users)."""
        logger.info("Creating user entries...")

        users_per_dept = {
            "engineering": 150,
            "marketing": 100,
            "sales": 100,
            "support": 100,
            "contractors": 50,
        }

        user_id = 1
        for dept, count in users_per_dept.items():
            for _ in range(count):
                first_name = random.choice(FIRST_NAMES)
                last_name = random.choice(LAST_NAMES)
                uid = f"user{user_id:04d}"
                cn = f"{first_name} {last_name}"
                dn = f"uid={uid},ou={dept},ou=users,{self.base_dn}"

                attributes: dict[str, str | FlextTypes.StringList] = {
                    FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS: [
                        FlextLdapConstants.ObjectClasses.INET_ORG_PERSON,
                        FlextLdapConstants.ObjectClasses.ORGANIZATIONAL_PERSON,
                        FlextLdapConstants.ObjectClasses.PERSON,
                        FlextLdapConstants.ObjectClasses.TOP,
                    ],
                    FlextLdapConstants.LdapAttributeNames.UID: uid,
                    FlextLdapConstants.LdapAttributeNames.CN: cn,
                    FlextLdapConstants.LdapAttributeNames.SN: last_name,
                    FlextLdapConstants.LdapAttributeNames.GIVEN_NAME: first_name,
                    FlextLdapConstants.LdapAttributeNames.MAIL: f"{uid}@flext.local",
                    FlextLdapConstants.LdapAttributeNames.DISPLAY_NAME: cn,
                    FlextLdapConstants.LdapAttributeNames.EMPLOYEE_NUMBER: str(user_id),
                    FlextLdapConstants.LdapAttributeNames.DEPARTMENT: dept,
                    FlextLdapConstants.LdapAttributeNames.TITLE: random.choice([
                        "Engineer",
                        "Manager",
                        "Analyst",
                        "Specialist",
                        "Coordinator",
                        "Director",
                        "Lead",
                        "Senior",
                        "Junior",
                        "Intern",
                    ]),
                }

                # Add optional attributes for some users
                if random.random() < 0.7:  # 70% have phone numbers
                    attributes[
                        FlextLdapConstants.LdapAttributeNames.TELEPHONE_NUMBER
                    ] = f"+1-555-{random.randint(1000, 9999)}"

                if random.random() < 0.5:  # 50% have mobile numbers
                    attributes[FlextLdapConstants.LdapAttributeNames.MOBILE] = (
                        f"+1-555-{random.randint(1000, 9999)}"
                    )

                if random.random() < 0.3:  # 30% have employee type
                    attributes[FlextLdapConstants.LdapAttributeNames.EMPLOYEE_TYPE] = (
                        random.choice([
                            "full-time",
                            "part-time",
                            "contractor",
                            "intern",
                        ])
                    )

                self.entries.append((dn, attributes))
                self.user_dns.append(dn)
                user_id += 1

    def _create_groups(self) -> None:
        """Create group entries (~50 groups)."""
        logger.info("Creating group entries...")

        # Department groups (10)
        for dept in DEPARTMENTS:
            cn = f"dept-{dept}"
            dn = f"cn={cn},ou=departments,ou=groups,{self.base_dn}"

            # Add random members from this department
            dept_users = [
                user_dn for user_dn in self.user_dns if f"ou={dept},ou=users" in user_dn
            ]
            members = random.sample(dept_users, min(10, len(dept_users)))

            attributes: dict[str, str | FlextTypes.StringList] = {
                FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS: [
                    FlextLdapConstants.ObjectClasses.GROUP_OF_NAMES,
                    FlextLdapConstants.ObjectClasses.TOP,
                ],
                FlextLdapConstants.LdapAttributeNames.CN: cn,
                FlextLdapConstants.LdapAttributeNames.DESCRIPTION: f"{dept.title()} department group",
                FlextLdapConstants.LdapAttributeNames.MEMBER: members
                or [self.user_dns[0]],
            }
            self.entries.append((dn, attributes))
            self.group_dns.append(dn)

        # Project groups (20)
        for project in PROJECTS:
            cn = f"project-{project}"
            dn = f"cn={cn},ou=projects,ou=groups,{self.base_dn}"

            # Add random members from any department
            members = random.sample(self.user_dns, random.randint(5, 20))

            attributes = {
                FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS: [
                    FlextLdapConstants.ObjectClasses.GROUP_OF_NAMES,
                    FlextLdapConstants.ObjectClasses.TOP,
                ],
                FlextLdapConstants.LdapAttributeNames.CN: cn,
                FlextLdapConstants.LdapAttributeNames.DESCRIPTION: f"Project {project} team",
                FlextLdapConstants.LdapAttributeNames.MEMBER: members,
            }
            self.entries.append((dn, attributes))
            self.group_dns.append(dn)

        # Role groups (20)
        for role in ROLES:
            cn = f"role-{role}"
            dn = f"cn={cn},ou=roles,ou=groups,{self.base_dn}"

            # Add random members
            members = random.sample(self.user_dns, random.randint(3, 15))

            attributes = {
                FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS: [
                    FlextLdapConstants.ObjectClasses.GROUP_OF_NAMES,
                    FlextLdapConstants.ObjectClasses.TOP,
                ],
                FlextLdapConstants.LdapAttributeNames.CN: cn,
                FlextLdapConstants.LdapAttributeNames.DESCRIPTION: f"Role: {role}",
                FlextLdapConstants.LdapAttributeNames.MEMBER: members,
            }
            self.entries.append((dn, attributes))
            self.group_dns.append(dn)

    def _create_service_accounts(self) -> None:
        """Create service account entries (~100)."""
        logger.info("Creating service account entries...")

        for i in range(100):
            service_type = random.choice(SERVICE_NAMES)
            instance = i % 10
            cn = f"{service_type}-{instance:02d}"
            dn = f"cn={cn},ou=services,{self.base_dn}"

            attributes: dict[str, str | FlextTypes.StringList] = {
                FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS: [
                    "simpleSecurityObject",
                    "applicationProcess",
                    FlextLdapConstants.ObjectClasses.TOP,
                ],
                FlextLdapConstants.LdapAttributeNames.CN: cn,
                FlextLdapConstants.LdapAttributeNames.DESCRIPTION: f"Service account for {service_type}",
                "userPassword": "{SSHA}service-password-placeholder",
            }
            self.entries.append((dn, attributes))

    def _create_computer_accounts(self) -> None:
        """Create computer account entries (~200)."""
        logger.info("Creating computer account entries...")

        for i in range(200):
            prefix = random.choice(COMPUTER_PREFIXES)
            cn = f"{prefix}{i:03d}"
            dn = f"cn={cn},ou=computers,{self.base_dn}"

            attributes: dict[str, str | FlextTypes.StringList] = {
                FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS: [
                    "device",
                    FlextLdapConstants.ObjectClasses.TOP,
                ],
                FlextLdapConstants.LdapAttributeNames.CN: cn,
                FlextLdapConstants.LdapAttributeNames.DESCRIPTION: f"Computer {cn}",
                "serialNumber": f"SN{i:06d}",
            }

            # Add MAC address for some computers
            if random.random() < 0.8:  # 80% have MAC addresses
                mac = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
                attributes["macAddress"] = mac

            self.entries.append((dn, attributes))

    def _create_containers(self) -> None:
        """Create additional container entries (~150)."""
        logger.info("Creating additional container entries...")

        # Create nested organizational structure under containers
        container_types = [
            "locations",
            "applications",
            "resources",
            "policies",
            "roles",
        ]

        for container_type in container_types:
            # Top level container
            dn = f"ou={container_type},ou=containers,{self.base_dn}"
            attributes: dict[str, str | FlextTypes.StringList] = {
                FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS: [
                    FlextLdapConstants.ObjectClasses.ORGANIZATIONAL_UNIT,
                    FlextLdapConstants.ObjectClasses.TOP,
                ],
                FlextLdapConstants.LdapAttributeNames.OU: container_type,
                FlextLdapConstants.LdapAttributeNames.DESCRIPTION: f"{container_type.title()} container",
            }
            self.entries.append((dn, attributes))

            # Create sub-containers (30 per type)
            for i in range(30):
                sub_name = f"{container_type}-sub-{i:02d}"
                sub_dn = (
                    f"ou={sub_name},ou={container_type},ou=containers,{self.base_dn}"
                )
                sub_attributes: dict[str, str | FlextTypes.StringList] = {
                    FlextLdapConstants.LdapAttributeNames.OBJECT_CLASS: [
                        FlextLdapConstants.ObjectClasses.ORGANIZATIONAL_UNIT,
                        FlextLdapConstants.ObjectClasses.TOP,
                    ],
                    FlextLdapConstants.LdapAttributeNames.OU: sub_name,
                    FlextLdapConstants.LdapAttributeNames.DESCRIPTION: f"Sub-container {i}",
                }
                self.entries.append((sub_dn, sub_attributes))

    def export_to_ldif(self, output_path: Path) -> FlextResult[bool]:
        """Export generated entries to LDIF file.

        Args:
            output_path: Path to output LDIF file

        Returns:
            FlextResult indicating success

        """
        logger.info(f"Exporting {len(self.entries)} entries to {output_path}")

        try:
            with output_path.open("w", encoding="utf-8") as f:
                for dn, attributes in self.entries:
                    # Write DN
                    f.write(f"dn: {dn}\n")

                    # Write attributes
                    for attr_name, attr_value in attributes.items():
                        if isinstance(attr_value, list):
                            for value in attr_value:
                                f.write(f"{attr_name}: {value}\n")
                        else:
                            f.write(f"{attr_name}: {attr_value}\n")

                    # Empty line between entries
                    f.write("\n")

            logger.info(f"✅ Exported {len(self.entries)} entries to {output_path}")
            return FlextResult[bool].ok(True)

        except Exception as e:
            logger.exception("Failed to export to LDIF")
            return FlextResult[bool].fail(f"LDIF export failed: {e}")


def main() -> int:
    """Generate test data for LDAP validation.

    Returns:
        Exit code (0 for success, 1 for failure)

    """
    parser = argparse.ArgumentParser(
        description="Generate ~1000 LDAP test entries for comprehensive validation"
    )
    parser.add_argument(
        "--server",
        choices=["openldap", "oud"],
        default="openldap",
        help="Server type (openldap or oud)",
    )
    parser.add_argument(
        "--base-dn",
        default=None,
        help="Base DN (default: dc=flext,dc=local for openldap, dc=invaliddc for oud)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output LDIF file path",
    )

    args = parser.parse_args()

    # Set defaults based on server type
    if args.base_dn is None:
        args.base_dn = (
            "dc=flext,dc=local" if args.server == "openldap" else "dc=invaliddc"
        )

    if args.output is None:
        args.output = Path(f"test_data_{args.server}.ldif")

    logger.info("=" * 60)
    logger.info("FLEXT-LDAP Test Data Generator")
    logger.info("=" * 60)
    logger.info(f"Server Type: {args.server}")
    logger.info(f"Base DN: {args.base_dn}")
    logger.info(f"Output File: {args.output}")
    logger.info("=" * 60)

    try:
        # Generate test data
        generator = TestDataGenerator(args.server, args.base_dn)
        result = generator.generate_all_data()

        if result.is_failure:
            logger.error(f"❌ Test data generation failed: {result.error}")
            return 1

        # Export to LDIF
        export_result = generator.export_to_ldif(args.output)
        if export_result.is_failure:
            logger.error(f"❌ LDIF export failed: {export_result.error}")
            return 1

        logger.info("\n%s", "=" * 60)
        logger.info("✅ Test data generation completed successfully!")
        logger.info(f"📊 Generated {len(generator.entries)} total entries")
        logger.info(f"📄 Output file: {args.output}")
        logger.info("=" * 60)

        return 0

    except KeyboardInterrupt:
        logger.info("\nOperation interrupted by user")
        return 1
    except Exception:
        logger.exception("Operation failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())

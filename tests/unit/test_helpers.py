"""Test helpers for constructing correct Entry objects and test data.

Provides factory functions for creating FlextLdifModels.Entry objects
using the modern API with proper dn and attributes structure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import FlextLdifModels


class EntryFactory:
    """Factory for creating correct FlextLdifModels.Entry objects."""

    @staticmethod
    def create_user_entry(
        dn: str,
        uid: str | None = None,
        cn: str | None = None,
        sn: str | None = None,
        given_name: str | None = None,
        mail: str | None = None,
        telephone_number: str | None = None,
        mobile: str | None = None,
        department: str | None = None,
        organizational_unit: str | None = None,
        title: str | None = None,
        organization: str | None = None,
        user_password: str | None = None,
        object_classes: list[str] | None = None,
        **extra_attributes: str | list[str],
    ) -> FlextLdifModels.Entry:
        """Create a proper user Entry with attributes.

        Args:
            dn: Distinguished Name
            uid: User ID
            cn: Common Name
            sn: Surname
            given_name: Given Name
            mail: Email
            telephone_number: Phone
            mobile: Mobile phone
            department: Department
            organizational_unit: OU
            title: Job title
            organization: Organization
            user_password: Password
            object_classes: Object classes list
            **extra_attributes: Additional LDAP attributes

        Returns:
            Properly constructed FlextLdifModels.Entry

        """
        attributes_dict: dict[str, list[str]] = {}

        # Add standard user attributes (ALL values must be lists for LdifAttributes)
        if object_classes:
            attributes_dict["objectClass"] = object_classes
        else:
            attributes_dict["objectClass"] = ["person", "inetOrgPerson", "top"]

        if uid:
            attributes_dict["uid"] = [uid] if isinstance(uid, str) else uid
        if cn:
            attributes_dict["cn"] = [cn] if isinstance(cn, str) else cn
        if sn:
            attributes_dict["sn"] = [sn] if isinstance(sn, str) else sn
        if given_name:
            attributes_dict["givenName"] = (
                [given_name] if isinstance(given_name, str) else given_name
            )
        if mail:
            attributes_dict["mail"] = [mail] if isinstance(mail, str) else mail
        if telephone_number:
            attributes_dict["telephoneNumber"] = (
                [telephone_number]
                if isinstance(telephone_number, str)
                else telephone_number
            )
        if mobile:
            attributes_dict["mobile"] = [mobile] if isinstance(mobile, str) else mobile
        if department:
            attributes_dict["department"] = (
                [department] if isinstance(department, str) else department
            )
        if organizational_unit:
            attributes_dict["ou"] = (
                [organizational_unit]
                if isinstance(organizational_unit, str)
                else organizational_unit
            )
        if title:
            attributes_dict["title"] = [title] if isinstance(title, str) else title
        if organization:
            attributes_dict["o"] = (
                [organization] if isinstance(organization, str) else organization
            )
        if user_password:
            attributes_dict["userPassword"] = (
                [user_password] if isinstance(user_password, str) else user_password
            )

        # Add any extra attributes (ensure they're lists)
        for key, value in extra_attributes.items():
            if isinstance(value, str):
                attributes_dict[key] = [value]
            else:
                attributes_dict[key] = value

        # Create and return proper Entry
        dn_obj = FlextLdifModels.DistinguishedName(value=dn)
        ldif_attrs = FlextLdifModels.LdifAttributes(attributes=attributes_dict)
        return FlextLdifModels.Entry(
            dn=dn_obj, attributes=ldif_attrs, entry_type="user"
        )

    @staticmethod
    def create_group_entry(
        dn: str,
        cn: str | None = None,
        members: list[str] | None = None,
        description: str | None = None,
        object_classes: list[str] | None = None,
        **extra_attributes: str | list[str],
    ) -> FlextLdifModels.Entry:
        """Create a proper group Entry with attributes.

        Args:
            dn: Distinguished Name
            cn: Common Name
            members: List of member DNs
            description: Group description
            object_classes: Object classes list
            **extra_attributes: Additional LDAP attributes

        Returns:
            Properly constructed FlextLdifModels.Entry

        """
        attributes_dict: dict[str, list[str]] = {}

        if object_classes:
            attributes_dict["objectClass"] = object_classes
        else:
            attributes_dict["objectClass"] = ["groupOfNames", "top"]

        if cn:
            attributes_dict["cn"] = [cn] if isinstance(cn, str) else cn
        if members:
            attributes_dict["member"] = members
        if description:
            attributes_dict["description"] = (
                [description] if isinstance(description, str) else description
            )

        # Add any extra attributes (ensure they're lists)
        for key, value in extra_attributes.items():
            if isinstance(value, str):
                attributes_dict[key] = [value]
            else:
                attributes_dict[key] = value

        # Create and return proper Entry
        dn_obj = FlextLdifModels.DistinguishedName(value=dn)
        ldif_attrs = FlextLdifModels.LdifAttributes(attributes=attributes_dict)
        return FlextLdifModels.Entry(
            dn=dn_obj, attributes=ldif_attrs, entry_type="group"
        )

    @staticmethod
    def create_generic_entry(
        dn: str,
        attributes: dict[str, str | list[str]],
        entry_type: str = "generic",
    ) -> FlextLdifModels.Entry:
        """Create a generic Entry with arbitrary attributes.

        Args:
            dn: Distinguished Name
            attributes: Dictionary of LDAP attributes
            entry_type: Type of entry (user, group, generic, etc.)

        Returns:
            Properly constructed FlextLdifModels.Entry

        """
        dn_obj = FlextLdifModels.DistinguishedName(value=dn)
        ldif_attrs = FlextLdifModels.LdifAttributes(attributes=attributes)
        return FlextLdifModels.Entry(
            dn=dn_obj, attributes=ldif_attrs, entry_type=entry_type
        )


__all__ = ["EntryFactory"]

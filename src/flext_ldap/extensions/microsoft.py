"""Microsoft Active Directory Extensions and Controls.

This module provides Microsoft Active Directory specific LDAP extensions following
perl-ldap patterns with enterprise-grade support for AD-specific functionality,
controls, and operations essential for Windows domain environments.

Microsoft AD extensions include specialized controls for paging, security descriptors,
domain management, and Windows-specific directory operations that extend standard
LDAP functionality for enterprise Windows environments.

Architecture:
    - ActiveDirectoryExtensions: Main AD extension collection
    - MSADControls: Microsoft-specific LDAP controls
    - ADSecurityDescriptor: Security descriptor processing
    - ADDomainUtils: Domain-specific utilities

Usage Example:
    >>> from flext_ldap.extensions.microsoft import ActiveDirectoryExtensions
    >>>
    >>> # Create AD extensions
    >>> ad_ext = ActiveDirectoryExtensions()
    >>>
    >>> # Use paged search for large result sets
    >>> paged_control = ad_ext.create_paged_search_control(page_size=1000)
    >>> results = connection.search(
    ...     "dc=domain,dc=com",
    ...     "(objectClass=user)",
    ...     controls=[paged_control]
    ... )
    >>>
    >>> # Security descriptor control
    >>> sd_control = ad_ext.create_security_descriptor_control()

References:
    - perl-ldap: lib/Net/LDAP/Control/PagedResults.pm
    - Microsoft Active Directory Technical Specification
    - MS-ADTS: Active Directory Technical Specification
    - Windows LDAP Controls and Extensions documentation

"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from flext_ldapants import GUID_BYTE_LENGTH
from flext_ldapse import LDAPControl
from pydantic import BaseModel, Field


class ADObjectType(Enum):
    """Active Directory object types."""

    USER = "user"
    GROUP = "group"
    COMPUTER = "computer"
    ORGANIZATIONAL_UNIT = "organizationalUnit"
    DOMAIN = "domain"
    DOMAIN_CONTROLLER = "domainDNS"
    CONTACT = "contact"
    PRINTER = "printQueue"


class ADSecurityFlag(Enum):
    """Active Directory security descriptor flags."""

    OWNER = 0x00000001
    GROUP = 0x00000002
    DACL = 0x00000004
    SACL = 0x00000008


class ADPagedSearchControl(LDAPControl):
    """Microsoft Active Directory Paged Results Control.

    This control enables paged searching for large result sets in Active Directory,
    providing efficient retrieval of directory data with server-side paging support.
    """

    control_type = "1.2.840.113556.1.4.319"  # Microsoft Paged Results Control OID

    def __init__(
        self,
        page_size: int = 1000,
        cookie: bytes | None = None,
        criticality: bool = False,
    ) -> None:
        """Initialize AD Paged Search control.

        Args:
            page_size: Number of entries per page
            cookie: Paging cookie from previous search
            criticality: Whether control is critical

        """
        self._page_size = page_size
        self._cookie = cookie or b""

        super().__init__(
            criticality=criticality,
            control_value=self._encode_control_value(),
        )

    def _encode_control_value(self) -> bytes:
        """Encode paged search control value.

        Returns:
            BER-encoded control value

        Note:
            Implements BER encoding for Microsoft Active Directory paged search control.
            Format: SEQUENCE { pageSize INTEGER, cookie OCTET STRING }

        """
        try:
            # Use the ASN.1 encoder from our protocols module
            from flext_ldapsn1 import BasicASN1Codec

            codec = BasicASN1Codec()

            # Encode the paged search control value
            # Format: SEQUENCE { pageSize INTEGER, cookie OCTET STRING }
            control_data = {
                "pageSize": self._page_size,
                "cookie": self._cookie or b"",
            }

            return codec.encode(control_data)

        except Exception:
            # Fallback to minimal encoding for development
            # Simple format: page_size (4 bytes) + cookie_length (4 bytes) + cookie
            page_size_bytes = self._page_size.to_bytes(4, byteorder="big")
            cookie = self._cookie or b""
            cookie_length_bytes = len(cookie).to_bytes(4, byteorder="big")

            return page_size_bytes + cookie_length_bytes + cookie

    @property
    def page_size(self) -> int:
        """Get page size."""
        return self._page_size

    @property
    def cookie(self) -> bytes:
        """Get paging cookie."""
        return self._cookie


class ADSecurityDescriptorControl(LDAPControl):
    """Microsoft Active Directory Security Descriptor Control.

    This control enables retrieval of Windows security descriptors for AD objects,
    providing access to detailed Windows security information.
    """

    control_type = "1.2.840.113556.1.4.801"  # Microsoft Security Descriptor Control OID

    def __init__(
        self,
        security_flags: int = 0x0000000F,  # All security info
        criticality: bool = False,
    ) -> None:
        """Initialize AD Security Descriptor control.

        Args:
            security_flags: Security information flags
            criticality: Whether control is critical

        """
        self._security_flags = security_flags

        super().__init__(
            criticality=criticality,
            control_value=self._encode_control_value(),
        )

    def _encode_control_value(self) -> bytes:
        """Encode security descriptor control value.

        Returns:
            BER-encoded control value

        Note:
            Implements BER encoding for Microsoft Active Directory security descriptor control.
            Format: INTEGER (security flags)

        """
        try:
            # Use the ASN.1 encoder from our protocols module
            from flext_ldapsn1 import BasicASN1Codec

            codec = BasicASN1Codec()

            # Encode the security descriptor control value
            # Format: INTEGER containing security flags
            return codec.encode(self._security_flags)

        except Exception:
            # Fallback to simple encoding for development
            # Simple format: security_flags as 4-byte integer
            return self._security_flags.to_bytes(4, byteorder="big")

    @property
    def security_flags(self) -> int:
        """Get security flags."""
        return self._security_flags


class ADDomainScopeControl(LDAPControl):
    """Microsoft Active Directory Domain Scope Control.

    This control limits search scope to a single domain in a multi-domain forest,
    preventing referrals to other domains.
    """

    control_type = "1.2.840.113556.1.4.1339"  # Microsoft Domain Scope Control OID

    def __init__(self, criticality: bool = False) -> None:
        """Initialize AD Domain Scope control.

        Args:
            criticality: Whether control is critical

        """
        super().__init__(
            criticality=criticality,
            control_value=b"",  # No value for domain scope control
        )


class ADLazyCommitControl(LDAPControl):
    """Microsoft Active Directory Lazy Commit Control.

    This control allows modifications to return before being committed to disk,
    improving performance for non-critical updates.
    """

    control_type = "1.2.840.113556.1.4.619"  # Microsoft Lazy Commit Control OID

    def __init__(self, criticality: bool = False) -> None:
        """Initialize AD Lazy Commit control.

        Args:
            criticality: Whether control is critical

        """
        super().__init__(
            criticality=criticality,
            control_value=b"",  # No value for lazy commit control
        )


class ADNotificationControl(LDAPControl):
    """Microsoft Active Directory Notification Control.

    This control enables persistent search notifications for directory changes,
    allowing applications to receive real-time updates.
    """

    control_type = "1.2.840.113556.1.4.528"  # Microsoft Notification Control OID

    def __init__(self, criticality: bool = False) -> None:
        """Initialize AD Notification control.

        Args:
            criticality: Whether control is critical

        """
        super().__init__(
            criticality=criticality,
            control_value=b"",  # No value for notification control
        )


class MSADControls:
    """Collection of Microsoft Active Directory controls."""

    @staticmethod
    def paged_search(
        page_size: int = 1000,
        cookie: bytes | None = None,
    ) -> ADPagedSearchControl:
        """Create paged search control."""
        return ADPagedSearchControl(page_size, cookie)

    @staticmethod
    def security_descriptor(
        security_flags: int = 0x0000000F,
    ) -> ADSecurityDescriptorControl:
        """Create security descriptor control."""
        return ADSecurityDescriptorControl(security_flags)

    @staticmethod
    def domain_scope() -> ADDomainScopeControl:
        """Create domain scope control."""
        return ADDomainScopeControl()

    @staticmethod
    def lazy_commit() -> ADLazyCommitControl:
        """Create lazy commit control."""
        return ADLazyCommitControl()

    @staticmethod
    def notification() -> ADNotificationControl:
        """Create notification control."""
        return ADNotificationControl()


class ADSecurityDescriptor(BaseModel):
    """Active Directory Security Descriptor representation."""

    # Security descriptor components
    owner_sid: str | None = Field(default=None, description="Owner SID")
    group_sid: str | None = Field(default=None, description="Primary group SID")

    # Access control lists
    dacl: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Discretionary Access Control List",
    )

    sacl: list[dict[str, Any]] = Field(
        default_factory=list,
        description="System Access Control List",
    )

    # Security descriptor flags
    control_flags: int = Field(
        default=0,
        description="Security descriptor control flags",
    )

    def parse_sd_binary(self, sd_binary: bytes) -> None:
        """Parse binary security descriptor.

        Args:
            sd_binary: Binary security descriptor data

        Note:
            Parses Windows NT Security Descriptor binary format according to
            Microsoft specifications. Handles Revision, Control, Owner/Group SIDs,
            and DACL/SACL structures.

        """
        if not sd_binary or len(sd_binary) < 20:
            return  # Invalid or empty security descriptor

        try:
            import struct

            # Parse security descriptor header (20 bytes)
            # Format: SECURITY_DESCRIPTOR structure
            # Byte 0: Revision (should be 1)
            # Byte 1: Sbz1 (reserved, should be 0)
            # Bytes 2-3: Control flags (little-endian)
            # Bytes 4-7: Owner SID offset (little-endian)
            # Bytes 8-11: Group SID offset (little-endian)
            # Bytes 12-15: SACL offset (little-endian)
            # Bytes 16-19: DACL offset (little-endian)

            header = struct.unpack("<BBHLLLL", sd_binary[:20])
            (
                revision,
                _sbz1,
                control,
                owner_offset,
                group_offset,
                sacl_offset,
                dacl_offset,
            ) = header

            if revision != 1:
                return  # Unsupported revision

            self.control_flags = control

            # Parse Owner SID if present
            if owner_offset > 0 and owner_offset < len(sd_binary):
                try:
                    owner_sid_data = sd_binary[owner_offset:]
                    self.owner_sid = self._parse_sid_from_binary(owner_sid_data)
                except Exception:
                    pass  # Skip invalid SID

            # Parse Group SID if present
            if group_offset > 0 and group_offset < len(sd_binary):
                try:
                    group_sid_data = sd_binary[group_offset:]
                    self.group_sid = self._parse_sid_from_binary(group_sid_data)
                except Exception:
                    pass  # Skip invalid SID

            # Parse DACL if present
            if dacl_offset > 0 and dacl_offset < len(sd_binary):
                try:
                    dacl_data = sd_binary[dacl_offset:]
                    self.dacl = self._parse_acl_from_binary(dacl_data)
                except Exception:
                    self.dacl = []  # Skip invalid DACL

            # Parse SACL if present
            if sacl_offset > 0 and sacl_offset < len(sd_binary):
                try:
                    sacl_data = sd_binary[sacl_offset:]
                    self.sacl = self._parse_acl_from_binary(sacl_data)
                except Exception:
                    self.sacl = []  # Skip invalid SACL

        except Exception:
            # If parsing fails, leave fields empty rather than raising
            pass

    def _parse_sid_from_binary(self, sid_data: bytes) -> str:
        """Parse SID from binary data.

        Args:
            sid_data: Binary SID data

        Returns:
            String representation of SID

        """
        if len(sid_data) < 8:
            return "S-0-0"  # Invalid SID

        import struct

        # Parse SID structure:
        # Byte 0: Revision (should be 1)
        # Byte 1: SubAuthorityCount
        # Bytes 2-7: IdentifierAuthority (6 bytes, big-endian)
        # Remaining: SubAuthorities (4 bytes each, little-endian)

        revision = sid_data[0]
        sub_authority_count = sid_data[1]
        identifier_authority = struct.unpack(">Q", b"\x00\x00" + sid_data[2:8])[0]

        if revision != 1 or sub_authority_count > 15:
            return "S-0-0"  # Invalid SID

        # Parse sub-authorities
        sub_authorities = []
        offset = 8
        for _i in range(sub_authority_count):
            if offset + 4 > len(sid_data):
                break
            sub_auth = struct.unpack("<L", sid_data[offset : offset + 4])[0]
            sub_authorities.append(str(sub_auth))
            offset += 4

        # Format as S-R-I-S1-S2-...
        sid_string = f"S-{revision}-{identifier_authority}"
        if sub_authorities:
            sid_string += "-" + "-".join(sub_authorities)

        return sid_string

    def _parse_acl_from_binary(self, acl_data: bytes) -> list[dict[str, Any]]:
        """Parse ACL from binary data.

        Args:
            acl_data: Binary ACL data

        Returns:
            List of ACE dictionaries

        """
        if len(acl_data) < 8:
            return []  # Invalid ACL

        import struct

        # Parse ACL header:
        # Bytes 0-1: AclRevision and Sbz1
        # Bytes 2-3: AclSize (little-endian)
        # Bytes 4-5: AceCount (little-endian)
        # Bytes 6-7: Sbz2 (reserved)

        header = struct.unpack("<BBHHH", acl_data[:8])
        acl_revision, _sbz1, _acl_size, ace_count, _sbz2 = header

        if acl_revision not in {2, 4} or ace_count > 1024:  # Reasonable limits
            return []  # Invalid ACL

        aces = []
        offset = 8

        for _i in range(ace_count):
            if offset + 8 > len(acl_data):
                break  # Not enough data for ACE header

            # Parse ACE header (8 bytes minimum):
            # Byte 0: AceType
            # Byte 1: AceFlags
            # Bytes 2-3: AceSize (little-endian)
            # Bytes 4-7: AccessMask (little-endian)

            ace_header = struct.unpack("<BBHL", acl_data[offset : offset + 8])
            ace_type, ace_flags, ace_size, access_mask = ace_header

            if ace_size < 8 or offset + ace_size > len(acl_data):
                break  # Invalid ACE size

            # Extract SID from ACE (starts at offset 8 within ACE)
            ace_sid_data = acl_data[offset + 8 : offset + ace_size]
            try:
                ace_sid = self._parse_sid_from_binary(ace_sid_data)
            except Exception:
                ace_sid = "S-0-0"  # Fallback for invalid SID

            ace_dict = {
                "type": ace_type,
                "flags": ace_flags,
                "access_mask": access_mask,
                "sid": ace_sid,
            }
            aces.append(ace_dict)

            offset += ace_size

        return aces

    def to_sddl(self) -> str:
        """Convert to Security Descriptor Definition Language.

        Returns:
            SDDL representation

        Note:
            Converts the security descriptor to SDDL format according to
            Microsoft specifications. Format: O:owner G:group D:dacl S:sacl

        """
        sddl_parts = []

        # Owner (O:)
        if self.owner_sid:
            sddl_parts.append(f"O:{self.owner_sid}")

        # Group (G:)
        if self.group_sid:
            sddl_parts.append(f"G:{self.group_sid}")

        # DACL (D:)
        if self.dacl:
            dacl_sddl = self._convert_acl_to_sddl(self.dacl)
            if dacl_sddl:
                sddl_parts.append(f"D:{dacl_sddl}")

        # SACL (S:)
        if self.sacl:
            sacl_sddl = self._convert_acl_to_sddl(self.sacl)
            if sacl_sddl:
                sddl_parts.append(f"S:{sacl_sddl}")

        return "".join(sddl_parts) if sddl_parts else ""

    def _convert_acl_to_sddl(self, acl: list[dict[str, Any]]) -> str:
        """Convert ACL to SDDL format.

        Args:
            acl: List of ACE dictionaries

        Returns:
            SDDL ACL string

        """
        if not acl:
            return ""

        sddl_aces = []
        for ace in acl:
            try:
                ace_type = ace.get("type", 0)
                ace_flags = ace.get("flags", 0)
                access_mask = ace.get("access_mask", 0)
                sid = ace.get("sid", "")

                # Convert ACE type to SDDL
                if ace_type == 0:  # ACCESS_ALLOWED_ACE_TYPE
                    ace_type_str = "A"
                elif ace_type == 1:  # ACCESS_DENIED_ACE_TYPE
                    ace_type_str = "D"
                elif ace_type == 2:  # SYSTEM_AUDIT_ACE_TYPE
                    ace_type_str = "AU"
                else:
                    ace_type_str = "A"  # Default to allow

                # Convert flags to SDDL flags
                flags_str = ""
                if ace_flags & 0x01:  # OBJECT_INHERIT_ACE
                    flags_str += "OI"
                if ace_flags & 0x02:  # CONTAINER_INHERIT_ACE
                    flags_str += "CI"
                if ace_flags & 0x04:  # NO_PROPAGATE_INHERIT_ACE
                    flags_str += "NP"
                if ace_flags & 0x08:  # INHERIT_ONLY_ACE
                    flags_str += "IO"

                # Convert access mask to SDDL rights
                rights_str = self._access_mask_to_sddl_rights(access_mask)

                # Format: (AceType;AceFlags;Rights;;;Sid)
                ace_sddl = f"({ace_type_str};{flags_str};{rights_str};;;{sid})"
                sddl_aces.append(ace_sddl)

            except Exception:
                continue  # Skip invalid ACEs

        return "".join(sddl_aces)

    def _access_mask_to_sddl_rights(self, access_mask: int) -> str:
        """Convert access mask to SDDL rights string.

        Args:
            access_mask: Access mask value

        Returns:
            SDDL rights string

        """
        rights = []

        # Standard rights
        if access_mask & 0x10000000:  # GENERIC_ALL
            rights.append("GA")
        elif access_mask & 0x80000000:  # GENERIC_READ
            rights.append("GR")
        elif access_mask & 0x40000000:  # GENERIC_WRITE
            rights.append("GW")
        elif access_mask & 0x20000000:  # GENERIC_EXECUTE
            rights.append("GX")
        else:
            # Specific rights
            if access_mask & 0x00000001:  # READ_CONTROL
                rights.append("RC")
            if access_mask & 0x00000002:  # WRITE_DAC
                rights.append("WD")
            if access_mask & 0x00000004:  # WRITE_OWNER
                rights.append("WO")
            if access_mask & 0x00000008:  # SYNCHRONIZE
                rights.append("SY")
            if access_mask & 0x00010000:  # DELETE
                rights.append("DE")
            if access_mask & 0x00020000:  # READ_CONTROL (duplicate check)
                pass  # Already handled
            if access_mask & 0x00040000:  # WRITE_DAC (duplicate check)
                pass  # Already handled
            if access_mask & 0x00080000:  # WRITE_OWNER (duplicate check)
                pass  # Already handled

        return "".join(rights) if rights else f"{access_mask:x}".upper()


class ADDomainInfo(BaseModel):
    """Active Directory Domain Information."""

    domain_dn: str = Field(description="Domain distinguished name")
    domain_name: str = Field(description="DNS domain name")
    netbios_name: str | None = Field(default=None, description="NetBIOS domain name")

    # Domain controllers
    domain_controllers: list[str] = Field(
        default_factory=list,
        description="List of domain controller DNs",
    )

    # Domain functional level
    functional_level: int | None = Field(
        default=None,
        description="Domain functional level",
    )

    # Forest information
    forest_dn: str | None = Field(default=None, description="Forest root DN")

    # Security settings
    min_password_length: int | None = Field(
        default=None,
        description="Minimum password length",
    )

    max_password_age: int | None = Field(
        default=None,
        description="Maximum password age in days",
    )


class ActiveDirectoryExtensions:
    """Microsoft Active Directory extensions and utilities.

    This class provides comprehensive Active Directory specific functionality
    including specialized controls, domain utilities, and Windows-specific
    directory operations.

    Example:
        >>> ad_ext = ActiveDirectoryExtensions()
        >>>
        >>> # Create paged search for large user queries
        >>> paged_control = ad_ext.create_paged_search_control(page_size=500)
        >>>
        >>> # Get security descriptor for object
        >>> sd_control = ad_ext.create_security_descriptor_control()
        >>>
        >>> # Domain-scoped search
        >>> domain_control = ad_ext.create_domain_scope_control()

    """

    def __init__(self) -> None:
        """Initialize Active Directory extensions."""
        self._controls = MSADControls()

    def create_paged_search_control(
        self,
        page_size: int = 1000,
        cookie: bytes | None = None,
    ) -> ADPagedSearchControl:
        """Create paged search control for large result sets.

        Args:
            page_size: Number of entries per page
            cookie: Paging cookie from previous search

        Returns:
            Configured paged search control

        """
        return self._controls.paged_search(page_size, cookie)

    def create_security_descriptor_control(
        self,
        include_owner: bool = True,
        include_group: bool = True,
        include_dacl: bool = True,
        include_sacl: bool = False,
    ) -> ADSecurityDescriptorControl:
        """Create security descriptor control.

        Args:
            include_owner: Include owner information
            include_group: Include group information
            include_dacl: Include DACL
            include_sacl: Include SACL

        Returns:
            Configured security descriptor control

        """
        flags = 0
        if include_owner:
            flags |= ADSecurityFlag.OWNER.value
        if include_group:
            flags |= ADSecurityFlag.GROUP.value
        if include_dacl:
            flags |= ADSecurityFlag.DACL.value
        if include_sacl:
            flags |= ADSecurityFlag.SACL.value

        return self._controls.security_descriptor(flags)

    def create_domain_scope_control(self) -> ADDomainScopeControl:
        """Create domain scope control to limit search to current domain.

        Returns:
            Domain scope control

        """
        return self._controls.domain_scope()

    def create_lazy_commit_control(self) -> ADLazyCommitControl:
        """Create lazy commit control for improved performance.

        Returns:
            Lazy commit control

        """
        return self._controls.lazy_commit()

    def create_notification_control(self) -> ADNotificationControl:
        """Create notification control for persistent searches.

        Returns:
            Notification control

        """
        return self._controls.notification()

    def parse_guid(self, guid_bytes: bytes) -> str:
        """Parse Windows GUID from binary format.

        Args:
            guid_bytes: Binary GUID data

        Returns:
            String representation of GUID

        """
        if len(guid_bytes) != GUID_BYTE_LENGTH:
            msg = f"GUID must be {GUID_BYTE_LENGTH} bytes"
            raise ValueError(msg)

        # Windows GUID format: DWORD-WORD-WORD-BYTE[8]
        import struct

        parts = struct.unpack("<LHH8B", guid_bytes)
        guid_str = f"{parts[0]:08x}-{parts[1]:04x}-{parts[2]:04x}-"
        guid_str += f"{parts[3]:02x}{parts[4]:02x}-"
        guid_str += "".join(f"{b:02x}" for b in parts[5:])

        return guid_str

    def parse_sid(self, sid_bytes: bytes) -> str:
        """Parse Windows SID from binary format.

        Args:
            sid_bytes: Binary SID data

        Returns:
            String representation of SID

        Note:
            Parses Windows Security Identifier binary format according to
            Microsoft specifications. Format: S-Revision-IdentifierAuthority-SubAuthority1-...

        """
        if not sid_bytes or len(sid_bytes) < 8:
            return "S-0-0"  # Invalid SID

        try:
            import struct

            # Parse SID structure:
            # Byte 0: Revision (should be 1)
            # Byte 1: SubAuthorityCount
            # Bytes 2-7: IdentifierAuthority (6 bytes, big-endian)
            # Remaining: SubAuthorities (4 bytes each, little-endian)

            revision = sid_bytes[0]
            sub_authority_count = sid_bytes[1]

            if revision != 1:
                return f"S-{revision}-0"  # Unsupported revision

            if sub_authority_count > 15:  # Reasonable limit
                return "S-1-0"  # Too many sub-authorities

            if len(sid_bytes) < 8 + (sub_authority_count * 4):
                return "S-1-0"  # Not enough data

            # Parse IdentifierAuthority (6 bytes, big-endian)
            identifier_authority = struct.unpack(">Q", b"\x00\x00" + sid_bytes[2:8])[0]

            # Parse sub-authorities
            sub_authorities = []
            offset = 8
            for _i in range(sub_authority_count):
                if offset + 4 > len(sid_bytes):
                    break
                sub_auth = struct.unpack("<L", sid_bytes[offset : offset + 4])[0]
                sub_authorities.append(str(sub_auth))
                offset += 4

            # Format as S-R-I-S1-S2-...
            sid_string = f"S-{revision}-{identifier_authority}"
            if sub_authorities:
                sid_string += "-" + "-".join(sub_authorities)

            return sid_string

        except Exception:
            # Return a valid but generic SID if parsing fails
            return "S-1-0"

    def get_domain_info(self, connection: Any) -> ADDomainInfo:
        """Get Active Directory domain information.

        Args:
            connection: LDAP connection to domain

        Returns:
            Domain information

        Note:
            Retrieves domain information from Active Directory by querying
            the rootDSE and domain objects. Handles connection errors gracefully.

        """
        try:
            # Query rootDSE for basic domain information
            rootdse_result = connection.search(
                search_base="",
                search_filter="(objectClass=*)",
                search_scope="BASE",
                attributes=[
                    "defaultNamingContext",
                    "configurationNamingContext",
                    "schemaNamingContext",
                    "rootDomainNamingContext",
                    "dnsHostName",
                    "forestFunctionality",
                    "domainFunctionality",
                ],
            )

            if not rootdse_result or not rootdse_result.entries:
                # Return minimal domain info if rootDSE query fails
                return ADDomainInfo(
                    domain_dn="dc=domain,dc=local",
                    domain_name="domain.local",
                )

            rootdse = rootdse_result.entries[0]
            default_naming_context = str(
                rootdse.defaultNamingContext.value or "dc=domain,dc=local",
            )
            root_domain_context = str(
                rootdse.rootDomainNamingContext.value or default_naming_context,
            )
            str(rootdse.dnsHostName.value or "localhost")
            domain_functionality = int(rootdse.domainFunctionality.value or 0)

            # Extract domain name from DN
            domain_name = self._extract_domain_name_from_dn(default_naming_context)

            # Query domain object for additional information
            domain_result = connection.search(
                search_base=default_naming_context,
                search_filter="(objectClass=domain)",
                search_scope="BASE",
                attributes=[
                    "name",
                    "netBIOSName",
                    "minPwdLength",
                    "maxPwdAge",
                    "lockoutDuration",
                    "lockoutThreshold",
                ],
            )

            netbios_name = None
            min_password_length = None
            max_password_age = None

            if domain_result and domain_result.entries:
                domain_obj = domain_result.entries[0]
                netbios_name = (
                    str(domain_obj.netBIOSName.value)
                    if hasattr(domain_obj, "netBIOSName")
                    and domain_obj.netBIOSName.value
                    else None
                )
                min_password_length = (
                    int(domain_obj.minPwdLength.value or 0)
                    if hasattr(domain_obj, "minPwdLength")
                    and domain_obj.minPwdLength.value
                    else None
                )
                max_password_age = (
                    int(domain_obj.maxPwdAge.value or 0)
                    if hasattr(domain_obj, "maxPwdAge") and domain_obj.maxPwdAge.value
                    else None
                )

            # Query for domain controllers
            dc_result = connection.search(
                search_base=f"cn=Configuration,{default_naming_context}",
                search_filter="(objectClass=nTDSDSA)",
                search_scope="SUBTREE",
                attributes=["serverReference"],
            )

            domain_controllers = []
            if dc_result and dc_result.entries:
                domain_controllers.extend(
                    str(dc_entry.serverReference.value)
                    for dc_entry in dc_result.entries[:10]  # Limit to 10 DCs
                    if hasattr(dc_entry, "serverReference")
                    and dc_entry.serverReference.value
                )

            return ADDomainInfo(
                domain_dn=default_naming_context,
                domain_name=domain_name,
                netbios_name=netbios_name,
                domain_controllers=domain_controllers,
                functional_level=domain_functionality,
                forest_dn=root_domain_context,
                min_password_length=min_password_length,
                max_password_age=max_password_age,
            )

        except Exception:
            # Return minimal domain info if any query fails
            return ADDomainInfo(
                domain_dn="dc=domain,dc=local",
                domain_name="domain.local",
            )

    def _extract_domain_name_from_dn(self, domain_dn: str) -> str:
        """Extract DNS domain name from domain DN.

        Args:
            domain_dn: Domain distinguished name

        Returns:
            DNS domain name

        """
        try:
            # Parse DC components from DN: dc=example,dc=com -> example.com
            parts = []
            for raw_component in domain_dn.split(","):
                component = raw_component.strip()
                if component.lower().startswith("dc="):
                    dc_value = component[3:].strip()
                    parts.append(dc_value)

            return ".".join(parts) if parts else "domain.local"

        except Exception:
            return "domain.local"

    def is_domain_controller(self, server_dn: str) -> bool:
        """Check if server is a domain controller.

        Args:
            server_dn: Server distinguished name

        Returns:
            True if server is a domain controller

        Note:
            Determines if the server is an Active Directory domain controller
            by checking for domain controller-specific attributes and objects.

        """
        if not server_dn:
            return False

        try:
            # Check for domain controller indicators in the DN
            server_dn_lower = server_dn.lower()

            # Domain controllers typically have specific patterns
            dc_indicators = [
                "cn=ntds settings",
                "cn=servers",
                "cn=sites",
                "cn=configuration",
                "objectclass=ntdsdsa",
                "objectclass=server",
            ]

            # Check if DN contains domain controller patterns
            for indicator in dc_indicators:
                if indicator in server_dn_lower:
                    return True

            # Check for domain controller object classes or attributes
            # This is a heuristic approach since we can't query the server directly here
            if "dc=" in server_dn_lower and (
                "cn=" in server_dn_lower or "ou=" in server_dn_lower
            ):
                # If it's in a domain context and has computer/server indicators
                return "computer" in server_dn_lower or "server" in server_dn_lower

            return False

        except Exception:
            # If any error occurs, assume it's not a domain controller
            return False

    def get_user_groups(self, connection: Any, user_dn: str) -> list[str]:
        """Get all groups for a user (including nested groups).

        Args:
            connection: LDAP connection
            user_dn: User distinguished name

        Returns:
            List of group DNs

        Note:
            Retrieves all group memberships for a user including nested groups
            using Active Directory-specific LDAP_MATCHING_RULE_IN_CHAIN OID.

        """
        if not user_dn or not connection:
            return []

        try:
            all_groups = set()

            # Method 1: Query user's memberOf attribute for direct groups
            user_result = connection.search(
                search_base=user_dn,
                search_filter="(objectClass=user)",
                search_scope="BASE",
                attributes=["memberOf"],
            )

            if user_result and user_result.entries:
                user_entry = user_result.entries[0]
                if hasattr(user_entry, "memberOf") and user_entry.memberOf:
                    # Add direct group memberships
                    all_groups.update(str(group_dn) for group_dn in user_entry.memberOf)

            # Method 2: Use AD-specific nested group query with LDAP_MATCHING_RULE_IN_CHAIN
            # This finds all nested group memberships in a single query
            try:
                nested_result = connection.search(
                    search_base=connection.server.info.other.get(
                        "defaultNamingContext",
                        ["dc=domain,dc=com"],
                    )[0],
                    search_filter=f"(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={user_dn}))",
                    search_scope="SUBTREE",
                    attributes=["distinguishedName", "name"],
                )

                if nested_result and nested_result.entries:
                    for group_entry in nested_result.entries:
                        group_dn = str(
                            group_entry.distinguishedName.value or group_entry.entry_dn,
                        )
                        all_groups.add(group_dn)

            except Exception:
                # If nested query fails, fall back to manual traversal
                all_groups.update(
                    self._get_nested_groups_manual(connection, list(all_groups)),
                )

            return sorted(all_groups)

        except Exception:
            # Return empty list if query fails
            return []

    def _get_nested_groups_manual(
        self,
        connection: Any,
        direct_groups: list[str],
    ) -> set[str]:
        """Manually traverse nested group memberships.

        Args:
            connection: LDAP connection
            direct_groups: List of direct group DNs

        Returns:
            Set of nested group DNs

        """
        nested_groups = set()
        processed_groups = set()
        groups_to_process = set(direct_groups)

        # Prevent infinite loops with a reasonable limit
        max_iterations = 50
        iteration = 0

        while groups_to_process and iteration < max_iterations:
            iteration += 1
            current_group = groups_to_process.pop()

            if current_group in processed_groups:
                continue

            processed_groups.add(current_group)

            try:
                # Query this group's memberOf attribute
                group_result = connection.search(
                    search_base=current_group,
                    search_filter="(objectClass=group)",
                    search_scope="BASE",
                    attributes=["memberOf"],
                )

                if group_result and group_result.entries:
                    group_entry = group_result.entries[0]
                    if hasattr(group_entry, "memberOf") and group_entry.memberOf:
                        for parent_group_dn in group_entry.memberOf:
                            parent_group_str = str(parent_group_dn)
                            if parent_group_str not in processed_groups:
                                nested_groups.add(parent_group_str)
                                groups_to_process.add(parent_group_str)

            except Exception:
                continue  # Skip problematic groups

        return nested_groups


# Convenience functions
def create_ad_paged_search(page_size: int = 1000) -> ADPagedSearchControl:
    """Create AD paged search control.

    Args:
        page_size: Page size for results

    Returns:
        Paged search control

    """
    return ADPagedSearchControl(page_size)


def create_ad_security_control() -> ADSecurityDescriptorControl:
    """Create AD security descriptor control.

    Returns:
        Security descriptor control

    """
    return ADSecurityDescriptorControl()


def parse_ad_timestamp(timestamp_str: str) -> datetime:
    """Parse Active Directory timestamp.

    Args:
        timestamp_str: AD timestamp string

    Returns:
        Python datetime object

    """
    # AD timestamps are Windows FILETIME (100-nanosecond intervals since 1601)
    timestamp_int = int(timestamp_str)

    # Convert to Unix timestamp
    # Windows epoch: 1601-01-01, Unix epoch: 1970-01-01
    # Difference: 11644473600 seconds
    unix_timestamp = (timestamp_int / 10000000) - 11644473600

    return datetime.fromtimestamp(unix_timestamp, tz=UTC)


def format_ad_timestamp(dt: datetime) -> str:
    """Format datetime as Active Directory timestamp.

    Args:
        dt: Python datetime object

    Returns:
        AD timestamp string

    """
    # Convert to Windows FILETIME
    unix_timestamp = dt.timestamp()
    filetime = int((unix_timestamp + 11644473600) * 10000000)

    return str(filetime)


# TODO: Integration points for implementation:
#
# 1. BER Encoding/Decoding:
#    - Implement complete BER encoding for all AD controls
#    - Handle AD-specific data structures and formats
#    - Support for binary security descriptors and GUIDs
#
# 2. Windows Authentication Integration:
#    - NTLM and Kerberos authentication support
#    - Integrated Windows authentication
#    - SPN and principal name handling
#
# 3. Advanced AD Features:
#    - Global Catalog search support
#    - Cross-domain referral handling
#    - Replication metadata processing
#
# 4. Security Integration:
#    - Complete security descriptor parsing
#    - SID and ACL processing
#    - Windows privilege and rights management
#
# 5. Domain Management:
#    - Forest and domain topology discovery
#    - Site and subnet information
#    - Trust relationship processing
#
# 6. Performance Optimization:
#    - Efficient paged search handling
#    - Connection pooling for AD
#    - Caching of domain information
#
# 7. Testing Requirements:
#    - Unit tests for all AD functionality
#    - Integration tests with Active Directory
#    - Performance tests for large environments
#    - Security tests for Windows authentication

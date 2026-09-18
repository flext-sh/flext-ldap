# from flext-ldap/docs/guides/acl-management.md:208
from flext_ldap import FlextLdapModels, FlextLdapConstants

# Create ACL components
target_result = FlextLdapModels.AclTarget.create(
    target_type=FlextLdapConstants.TargetType.ATTRIBUTES,
    attributes=["userPassword"],
    dn_pattern="ou=users,dc=example,dc=com",
)

subject_result = FlextLdapModels.AclSubject.create(
    subject_type=FlextLdapConstants.SubjectType.SELF, identifier="self"
)

permissions_result = FlextLdapModels.AclPermissions.create(
    permissions=[FlextLdapConstants.Permission.WRITE], grant_type="allow"
)

# Create unified ACL
unified_result = FlextLdapModels.Acl.create(
    name="Allow self password write",
    target=target_result.unwrap(),
    subject=subject_result.unwrap(),
    permissions=permissions_result.unwrap(),
    priority=100,
)

# Convert to any format
api.convert_to_openldap(unified_result.unwrap())
api.convert_to_oracle(unified_result.unwrap())
api.convert_to_aci(unified_result.unwrap())```
## ACL Validation


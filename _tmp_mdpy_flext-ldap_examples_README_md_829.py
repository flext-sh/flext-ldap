# from flext-ldap_examples/README.md:829
from flext_ldap import FlextLdapValidations

# Validate DN
dn_result = FlextLdapValidations.validate_dn(user_dn)
if dn_result.is_failure:
    logger.error(f"Invalid DN: {dn_result.error}")
    return

# Validate filter
filter_result = FlextLdapValidations.validate_filter(filter_str)
if filter_result.is_failure:
    logger.error(f"Invalid filter: {filter_result.error}")
    return

# Proceed with operation
result = api.search(base_dn=user_dn, filter_str=filter_str)

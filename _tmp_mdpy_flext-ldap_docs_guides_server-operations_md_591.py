# from flext-ldap_docs/guides/server-operations.md:591
from flext_ldap import FlextLdapServersAdapter

servers = FlextLdapServersAdapter()

# Detect server type from entries
entries = [...]  # List of FlextLdifModels.Entry
server_type_result = servers.detect_server_type_from_entries(entries)

if server_type_result.success:
    server_type = server_type_result.unwrap()
    print(f"Detected server: {server_type}")

    # Get server-specific information
    acl_attr_result = servers.get_acl_attribute_name(server_type)
    schema_dn_result = servers.get_schema_subentry(server_type)
    acl_format_result = servers.get_acl_format(server_type)

    print(f"ACL attribute: {acl_attr_result.unwrap()}")
    print(f"Schema DN: {schema_dn_result.unwrap()}")
    print(f"ACL format: {acl_format_result.unwrap()}")

# Automatic server operations selection
if server_type == "openldap2":
    ops = OpenLDAP2Operations()
elif server_type == "oid":
    ops = OracleOIDOperations()
elif server_type == "oud":
    ops = OracleOUDOperations()
else:
    ops = GenericServerOperations()```
##

## 📊 Server Comparison

### **Connection Features**

Feature: Default Port - OpenLDAP 2.x: 389/636 - OpenLDAP 1.x: 389/636 - Oracle OID: 389/636 - Oracle OUD: 389/636 - AD: 389/636 - Generic: 389/636
Feature: START_TLS - OpenLDAP 2.x: ✅ Yes - OpenLDAP 1.x: ✅ Yes - Oracle OID: ✅ Yes - Oracle OUD: ✅ Yes - AD: ❌ No - Generic: ✅ Yes
Feature: SIMPLE Auth - OpenLDAP 2.x: ✅ Yes - OpenLDAP 1.x: ✅ Yes - Oracle OID: ✅ Yes - Oracle OUD: ✅ Yes - AD: ✅ Yes - Generic: ✅ Yes
Feature: SASL/EXTERNAL - OpenLDAP 2.x: ✅ Yes - OpenLDAP 1.x: ❌ No - Oracle OID: ✅ Yes - Oracle OUD: ✅ Yes - AD: ❌ No - Generic: ❌ No
Feature: SASL/GSSAPI - OpenLDAP 2.x: ❌ No - OpenLDAP 1.x: ❌ No - Oracle OID: ❌ No - Oracle OUD: ✅ Yes - AD: ✅ Yes - Generic: ❌ No

### **Schema Operations**

Feature: Schema DN - OpenLDAP 2.x: cn=subschema - OpenLDAP 1.x: cn=subschema - Oracle OID: cn=subschemasubentry - Oracle OUD: cn=schema - AD: cn=schema,cn=settings - Generic: cn=subschema
Feature: Object Classes - OpenLDAP 2.x: ✅ Full - OpenLDAP 1.x: ✅ Full - Oracle OID: ✅ Full - Oracle OUD: ✅ Full - AD: 🟡 Stub - Generic: ⚠️ Basic
Feature: Attribute Types - OpenLDAP 2.x: ✅ Full - OpenLDAP 1.x: ✅ Full - Oracle OID: ✅ Full - Oracle OUD: ✅ Full - AD: 🟡 Stub - Generic: ⚠️ Basic
Feature: Syntaxes - OpenLDAP 2.x: ✅ Yes - OpenLDAP 1.x: ✅ Yes - Oracle OID: ❌ No - Oracle OUD: ✅ Yes - AD: 🟡 Stub - Generic: ❌ No
Feature: Matching Rules - OpenLDAP 2.x: ✅ Yes - OpenLDAP 1.x: ❌ No - Oracle OID: ❌ No - Oracle OUD: ❌ No - AD: 🟡 Stub - Generic: ❌ No

### **ACL Features**

Feature: ACL Attribute - OpenLDAP 2.x: olcAccess - OpenLDAP 1.x: access - Oracle OID: orclaci - Oracle OUD: ds-privilege-name - AD: nTSecurityDescriptor - Generic: aci
Feature: Get ACLs - OpenLDAP 2.x: ✅ Full - OpenLDAP 1.x: ✅ Full - Oracle OID: ✅ Full - Oracle OUD: ✅ Full - AD: 🟡 Stub - Generic: ⚠️ Limited
Feature: Set ACLs - OpenLDAP 2.x: ✅ Full - OpenLDAP 1.x: ✅ Full - Oracle OID: ✅ Full - Oracle OUD: ✅ Full - AD: 🟡 Stub - Generic: ❌ No
Feature: Parse ACL - OpenLDAP 2.x: ✅ Full - OpenLDAP 1.x: ✅ Full - Oracle OID: ⚠️ Basic - Oracle OUD: ⚠️ Basic - AD: 🟡 Stub - Generic: ⚠️ Basic
Feature: Format ACL - OpenLDAP 2.x: ✅ Full - OpenLDAP 1.x: ✅ Full - Oracle OID: ⚠️ Basic - Oracle OUD: ⚠️ Basic - AD: 🟡 Stub - Generic: ⚠️ Basic

### **Search Features**

Feature: Paged Results - OpenLDAP 2.x: ✅ Yes - OpenLDAP 1.x: ✅ Yes - Oracle OID: ✅ Yes - Oracle OUD: ✅ Yes - AD: ✅ Yes - Generic: ✅ Yes
Feature: VLV - OpenLDAP 2.x: ✅ Yes - OpenLDAP 1.x: ⚠️ Limited - Oracle OID: ✅ Yes - Oracle OUD: ✅ Yes - AD: ❌ No - Generic: ❌ No
Feature: Max Page Size - OpenLDAP 2.x: 1000 - OpenLDAP 1.x: 1000 - Oracle OID: 5000 - Oracle OUD: 1000 - AD: 1000 - Generic: 1000

##

## 🎯 Best Practices

### **1. Use Server Detection**

Always detect the server type for optimal operations:


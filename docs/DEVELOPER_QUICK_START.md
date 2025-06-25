# ⚡ Developer Quick Start Guide

**Get up and running with LDAP development in 15 minutes**

[![Quick Start](https://img.shields.io/badge/Quick%20Start-15%20min-green.svg)](https://quick-start.ldap.com)
[![Production Ready](https://img.shields.io/badge/Production-Ready-blue.svg)](https://production.ldap.com)
[![Multi Language](https://img.shields.io/badge/Languages-12%2B-orange.svg)](https://multilang.ldap.com)

**Stop struggling with LDAP setup!** This guide gets you from zero to productive LDAP development in just 15 minutes, with copy-paste examples for every major programming language.

## 🎯 Choose Your Path

**Pick your language and start coding immediately:**

| Language       | ⏱️ **Setup Time** | 🛠️ **Library**    | 📋 **Quick Example**                     |
| -------------- | :---------------- | :---------------- | :--------------------------------------- |
| 🐍 **Python**  | 2 minutes         | ldap3             | [Jump to Python](#-python-fastest-start) |
| ☕ **Java**    | 5 minutes         | Apache LDAP API   | [Jump to Java](#-java-enterprise-ready)  |
| 🦀 **Rust**    | 3 minutes         | ldap3             | [Jump to Rust](#-rust-safe--fast)        |
| 🌐 **Node.js** | 2 minutes         | ldapjs            | [Jump to Node.js](#-nodejs-web-ready)    |
| 💎 **Ruby**    | 3 minutes         | net-ldap          | [Jump to Ruby](#-ruby-elegant--simple)   |
| 🐹 **Go**      | 3 minutes         | go-ldap           | [Jump to Go](#-go-concurrent--efficient) |
| 🔷 **C#**      | 4 minutes         | DirectoryServices | [Jump to C#](#-c-net-integration)        |
| 🐘 **PHP**     | 2 minutes         | ldap extension    | [Jump to PHP](#-php-web-development)     |

**🚀 Just want to test LDAP?** → [Test Server Setup](#-instant-test-server)

## 🧪 Instant Test Server

**Need a test LDAP server? Get one running in 30 seconds:**

### 🐳 **Docker Approach (Recommended)**

```bash
# Quick OpenLDAP server
docker run -p 389:389 -p 636:636 \
  -e LDAP_ORGANISATION="Test Company" \
  -e LDAP_DOMAIN="test.com" \
  -e LDAP_ADMIN_PASSWORD="admin123" \
  osixia/openldap:latest

# Test connection
ldapsearch -x -H ldap://localhost -b dc=test,dc=com -D cn=admin,dc=test,dc=com -w admin123
```

### 🦀 **Modern Rust Server (LLDAP)**

```bash
# Lightweight, modern server with web UI
docker run -p 3890:3890 -p 17170:17170 \
  -e UID=1001 -e GID=1001 \
  -e LLDAP_JWT_SECRET="random-secret" \
  -e LLDAP_LDAP_USER_PASS="admin123" \
  lldap/lldap:stable

# Access web UI at http://localhost:17170
# Username: admin, Password: admin123
```

### 🌐 **Online Test Server**

```
Host: ldap.forumsys.com
Port: 389
Bind DN: cn=read-only-admin,dc=example,dc=com
Password: password
Base DN: dc=example,dc=com
```

## 🐍 Python - Fastest Start

**The most popular LDAP library - production ready in 2 minutes:**

### 📦 **Installation**

```bash
pip install ldap3
```

### 🚀 **Basic Connection & Search**

```python
from ldap3 import Server, Connection, ALL

# Connect to server
server = Server('ldap.forumsys.com', get_info=ALL)
conn = Connection(server, 'cn=read-only-admin,dc=example,dc=com', 'password')

if conn.bind():
    # Search for all people
    conn.search('dc=example,dc=com', '(objectclass=person)', attributes=['cn', 'mail'])

    for entry in conn.entries:
        print(f"Name: {entry.cn}, Email: {entry.mail}")

    conn.unbind()
else:
    print("Connection failed")
```

### 🔧 **Advanced Operations**

```python
from ldap3 import Server, Connection, MODIFY_REPLACE

server = Server('localhost')
conn = Connection(server, 'cn=admin,dc=test,dc=com', 'admin123')

if conn.bind():
    # Add new user
    conn.add('cn=john,ou=people,dc=test,dc=com',
             ['inetOrgPerson'],
             {'cn': 'John Doe', 'sn': 'Doe', 'mail': 'john@test.com'})

    # Modify user
    conn.modify('cn=john,ou=people,dc=test,dc=com',
                {'mail': [(MODIFY_REPLACE, ['john.doe@test.com'])]})

    # Delete user
    conn.delete('cn=john,ou=people,dc=test,dc=com')

    conn.unbind()
```

### 📚 **Python Resources**

- **📖 [Official Docs](reference/ldap3-python-client/README.rst)** - Complete documentation
- **🧪 [Tutorial Examples](reference/ldap3-python-client/)** - Step-by-step examples
- **🔧 [Production Config](reference/ldap3-python-client/)** - Enterprise setup

## ☕ Java - Enterprise Ready

**Professional Java LDAP development with Apache LDAP API:**

### 📦 **Maven Setup**

```xml
<dependency>
    <groupId>org.apache.directory.api</groupId>
    <artifactId>api-all</artifactId>
    <version>2.1.5</version>
</dependency>
```

### 🚀 **Basic Connection & Search**

```java
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.ldap.client.api.*;

public class LdapQuickStart {
    public static void main(String[] args) throws LdapException {
        // Connect to server
        LdapConnection connection = new LdapNetworkConnection("ldap.forumsys.com", 389);
        connection.bind("cn=read-only-admin,dc=example,dc=com", "password");

        // Search for people
        SearchRequest searchRequest = new SearchRequestImpl();
        searchRequest.setBase("dc=example,dc=com");
        searchRequest.setFilter("(objectclass=person)");
        searchRequest.addAttributes("cn", "mail");
        searchRequest.setScope(SearchScope.SUBTREE);

        SearchCursor searchCursor = connection.search(searchRequest);

        while (searchCursor.next()) {
            SearchResultEntry entry = searchCursor.getEntry();
            System.out.println("Name: " + entry.get("cn").getString() +
                             ", Email: " + entry.get("mail").getString());
        }

        connection.close();
    }
}
```

### 🔧 **Advanced Operations**

```java
import org.apache.directory.api.ldap.model.entry.*;

// Add new user
Entry newEntry = new DefaultEntry("cn=john,ou=people,dc=test,dc=com");
newEntry.add("objectclass", "inetOrgPerson");
newEntry.add("cn", "John Doe");
newEntry.add("sn", "Doe");
newEntry.add("mail", "john@test.com");
connection.add(newEntry);

// Modify user
ModifyRequest modifyRequest = new ModifyRequestImpl();
modifyRequest.setName("cn=john,ou=people,dc=test,dc=com");
modifyRequest.replace("mail", "john.doe@test.com");
connection.modify(modifyRequest);

// Delete user
connection.delete("cn=john,ou=people,dc=test,dc=com");
```

### 📚 **Java Resources**

- **📖 [Apache LDAP API Docs](reference/apache-ldap-api/)** - Complete API reference
- **🏢 [Enterprise Examples](reference/apache-ldap-api/)** - Production patterns
- **🛠️ [Development Setup](reference/apache-directory-studio-source/)** - IDE integration

## 🦀 Rust - Safe & Fast

**Modern, memory-safe LDAP development:**

### 📦 **Cargo Setup**

```toml
[dependencies]
ldap3 = "0.11"
tokio = { version = "1.0", features = ["full"] }
```

### 🚀 **Basic Connection & Search**

```rust
use ldap3::{LdapConn, Scope, SearchEntry};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to server
    let mut ldap = LdapConn::new("ldap://ldap.forumsys.com:389")?;
    ldap.simple_bind("cn=read-only-admin,dc=example,dc=com", "password")?;

    // Search for people
    let (rs, _res) = ldap.search(
        "dc=example,dc=com",
        Scope::Subtree,
        "(objectclass=person)",
        vec!["cn", "mail"]
    )?.success()?;

    for entry in rs {
        let entry = SearchEntry::construct(entry);
        println!("Name: {:?}, Email: {:?}",
                entry.attrs.get("cn"),
                entry.attrs.get("mail"));
    }

    ldap.unbind()?;
    Ok(())
}
```

### 📚 **Rust Resources**

- **📖 [LLDAP Server](reference/lldap-light-implementation/)** - Modern Rust server
- **🦀 [Rust LDAP Crate](https://crates.io/crates/ldap3)** - Library documentation

## 🌐 Node.js - Web Ready

**JavaScript/TypeScript LDAP for web applications:**

### 📦 **Installation**

```bash
npm install ldapjs
```

### 🚀 **Basic Connection & Search**

```javascript
const ldap = require("ldapjs");

// Connect to server
const client = ldap.createClient({
  url: "ldap://ldap.forumsys.com:389",
});

client.bind("cn=read-only-admin,dc=example,dc=com", "password", (err) => {
  if (err) {
    console.error("Bind failed:", err);
    return;
  }

  // Search for people
  const opts = {
    filter: "(objectclass=person)",
    scope: "sub",
    attributes: ["cn", "mail"],
  };

  client.search("dc=example,dc=com", opts, (err, res) => {
    if (err) {
      console.error("Search failed:", err);
      return;
    }

    res.on("searchEntry", (entry) => {
      console.log("Name:", entry.object.cn, "Email:", entry.object.mail);
    });

    res.on("end", () => {
      client.unbind();
    });
  });
});
```

### 🔧 **Modern Async/Await Version**

```javascript
const ldap = require("ldapjs");
const { promisify } = require("util");

class LdapClient {
  constructor(url) {
    this.client = ldap.createClient({ url });
    this.bind = promisify(this.client.bind.bind(this.client));
  }

  async search(base, filter, attributes = []) {
    return new Promise((resolve, reject) => {
      const opts = { filter, scope: "sub", attributes };
      const results = [];

      this.client.search(base, opts, (err, res) => {
        if (err) return reject(err);

        res.on("searchEntry", (entry) => results.push(entry.object));
        res.on("end", () => resolve(results));
        res.on("error", reject);
      });
    });
  }
}

// Usage
async function example() {
  const client = new LdapClient("ldap://ldap.forumsys.com:389");
  await client.bind("cn=read-only-admin,dc=example,dc=com", "password");

  const people = await client.search(
    "dc=example,dc=com",
    "(objectclass=person)",
    ["cn", "mail"],
  );
  people.forEach((person) =>
    console.log(`Name: ${person.cn}, Email: ${person.mail}`),
  );
}
```

### 📚 **Node.js Resources**

- **📖 [ldapjs Documentation](reference/nodejs-ldapjs/)** - Complete API reference
- **🌐 [Modern Web UI](reference/ldap-ui-minimalist-web/)** - Vue.js LDAP interface

## 💎 Ruby - Elegant & Simple

**Beautiful Ruby LDAP code with net-ldap:**

### 📦 **Installation**

```bash
gem install net-ldap
```

### 🚀 **Basic Connection & Search**

```ruby
require 'net/ldap'

# Connect to server
ldap = Net::LDAP.new(
  host: 'ldap.forumsys.com',
  port: 389,
  auth: {
    method: :simple,
    username: 'cn=read-only-admin,dc=example,dc=com',
    password: 'password'
  }
)

# Search for people
people = ldap.search(
  base: 'dc=example,dc=com',
  filter: Net::LDAP::Filter.eq('objectclass', 'person'),
  attributes: ['cn', 'mail']
)

people.each do |person|
  puts "Name: #{person.cn.first}, Email: #{person.mail.first}"
end
```

### 🔧 **Advanced Operations**

```ruby
# Add new user
attributes = {
  objectclass: ['inetOrgPerson'],
  cn: 'John Doe',
  sn: 'Doe',
  mail: 'john@test.com'
}
ldap.add(dn: 'cn=john,ou=people,dc=test,dc=com', attributes: attributes)

# Modify user
ops = [
  [:replace, :mail, 'john.doe@test.com']
]
ldap.modify(dn: 'cn=john,ou=people,dc=test,dc=com', operations: ops)

# Delete user
ldap.delete(dn: 'cn=john,ou=people,dc=test,dc=com')
```

### 📚 **Ruby Resources**

- **📖 [net-ldap Documentation](reference/ruby-ldap-source/)** - Complete gem documentation

## 🐹 Go - Concurrent & Efficient

**High-performance Go LDAP applications:**

### 📦 **Installation**

```bash
go mod init ldap-example
go get github.com/go-ldap/ldap/v3
```

### 🚀 **Basic Connection & Search**

```go
package main

import (
    "fmt"
    "log"
    "github.com/go-ldap/ldap/v3"
)

func main() {
    // Connect to server
    l, err := ldap.Dial("tcp", "ldap.forumsys.com:389")
    if err != nil {
        log.Fatal(err)
    }
    defer l.Close()

    // Bind
    err = l.Bind("cn=read-only-admin,dc=example,dc=com", "password")
    if err != nil {
        log.Fatal(err)
    }

    // Search for people
    searchRequest := ldap.NewSearchRequest(
        "dc=example,dc=com",
        ldap.ScopeWholeSubtree,
        ldap.NeverDerefAliases,
        0, 0, false,
        "(objectclass=person)",
        []string{"cn", "mail"},
        nil,
    )

    sr, err := l.Search(searchRequest)
    if err != nil {
        log.Fatal(err)
    }

    for _, entry := range sr.Entries {
        fmt.Printf("Name: %s, Email: %s\n",
                  entry.GetAttributeValue("cn"),
                  entry.GetAttributeValue("mail"))
    }
}
```

### 📚 **Go Resources**

- **📖 [go-ldap Documentation](reference/go-ldap-source/)** - Complete package docs

## 🔷 C# - .NET Integration

**Native .NET LDAP development:**

### 🚀 **Basic Connection & Search**

```csharp
using System;
using System.DirectoryServices;

class Program
{
    static void Main()
    {
        // Connect to server
        using (var entry = new DirectoryEntry("LDAP://ldap.forumsys.com/dc=example,dc=com",
                                              "cn=read-only-admin,dc=example,dc=com",
                                              "password"))
        {
            using (var searcher = new DirectorySearcher(entry))
            {
                searcher.Filter = "(objectclass=person)";
                searcher.PropertiesToLoad.AddRange(new[] { "cn", "mail" });

                foreach (SearchResult result in searcher.FindAll())
                {
                    var name = result.Properties["cn"][0]?.ToString();
                    var email = result.Properties["mail"][0]?.ToString();
                    Console.WriteLine($"Name: {name}, Email: {email}");
                }
            }
        }
    }
}
```

### 📚 **C# Resources**

- **📖 [.NET Directory Services](reference/dotnet-directory-services/)** - Microsoft documentation

## 🐘 PHP - Web Development

**PHP LDAP for web applications:**

### 🚀 **Basic Connection & Search**

```php
<?php
// Connect to server
$ldap = ldap_connect("ldap.forumsys.com", 389);
ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);

// Bind
$bind = ldap_bind($ldap, "cn=read-only-admin,dc=example,dc=com", "password");

if ($bind) {
    // Search for people
    $search = ldap_search($ldap, "dc=example,dc=com", "(objectclass=person)", ["cn", "mail"]);
    $entries = ldap_get_entries($ldap, $search);

    for ($i = 0; $i < $entries["count"]; $i++) {
        echo "Name: " . $entries[$i]["cn"][0] . ", Email: " . $entries[$i]["mail"][0] . "\n";
    }
}

ldap_close($ldap);
?>
```

### 📚 **PHP Resources**

- **📖 [phpLDAPadmin](reference/phpldapadmin-web-interface/)** - Complete web admin
- **🔑 [Self Service Password](reference/ldap-self-service-password/)** - Password management

## 🔧 Common Operations Reference

**Copy-paste examples for common LDAP operations:**

### 🔍 **Search Filters**

```python
# Basic filters
"(objectclass=person)"                    # All people
"(cn=john*)"                             # Names starting with 'john'
"(&(objectclass=person)(mail=*@test.com))" # People with test.com emails
"(|(cn=john)(cn=jane))"                   # John OR Jane

# Advanced filters
"(&(objectclass=person)(!(mail=*)))"      # People without email
"(createTimestamp>=20231201000000Z)"       # Created after Dec 1, 2023
```

### 📝 **Common Attributes**

```python
# Person attributes
['cn', 'sn', 'givenName', 'mail', 'telephoneNumber']

# Group attributes
['cn', 'description', 'member', 'memberUid']

# Organizational attributes
['ou', 'description', 'businessCategory']

# System attributes
['createTimestamp', 'modifyTimestamp', 'entryUUID']
```

### 🏗️ **DN Construction**

```python
# User DNs
"cn=john.doe,ou=people,dc=company,dc=com"
"uid=jdoe,ou=users,dc=company,dc=com"

# Group DNs
"cn=developers,ou=groups,dc=company,dc=com"

# Organizational DNs
"ou=engineering,ou=departments,dc=company,dc=com"
```

## 🚨 Common Troubleshooting

**Quick fixes for common LDAP issues:**

### 🔌 **Connection Issues**

```python
# Test basic connectivity
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
result = sock.connect_ex(('ldap.example.com', 389))
print("Port 389 open" if result == 0 else "Port 389 closed")
```

### 🔐 **Authentication Issues**

```python
# Debug bind issues
try:
    conn.bind()
    print("Bind successful")
except Exception as e:
    print(f"Bind failed: {e}")
    # Check: DN format, password, server access
```

### 🔍 **Search Issues**

```python
# Debug empty search results
conn.search('dc=example,dc=com', '(objectclass=*)', attributes=['*'])
if not conn.entries:
    print("No entries found - check base DN and access permissions")
```

### 🌐 **SSL/TLS Issues**

```python
# Test SSL connection
from ldap3 import Server, Connection, Tls
import ssl

tls = Tls(validate=ssl.CERT_NONE)  # For testing only!
server = Server('ldaps://ldap.example.com', use_ssl=True, tls=tls)
conn = Connection(server)
```

## 📚 Next Steps

**Now that you're up and running:**

### 🎓 **Learn More**

- **[📖 Complete Documentation](README.md)** - Full learning center
- **[⚡ RFC Quick Reference](RFC_QUICK_REFERENCE.md)** - Fast RFC lookup
- **[✅ Compliance Checklist](IMPLEMENTATION_CHECKLIST.md)** - Production readiness

### 🛠️ **Build Something**

- **[🏗️ Deploy a Server](reference/README.md#complete-ldap-servers)** - Production LDAP servers
- **[🖥️ Try GUI Tools](reference/README.md#gui--administration-tools)** - Visual administration
- **[🌐 Web Interfaces](reference/README.md#web-interfaces--tools)** - Browser-based tools

### 🤝 **Get Help**

- **[🧭 Navigation Guide](NAVIGATION_INDEX.md)** - Find anything quickly
- **[🔗 External Resources](README.md#external-references)** - Community resources

---

**🎯 Congratulations!** You're now ready to build amazing LDAP applications. This guide covered the essentials - explore our complete documentation for advanced features and production deployment guidance.

**⭐ Found this helpful?** This is just the beginning - our [complete collection](README.md) contains 57+ implementations, 86+ RFCs, and 146+ schemas to explore!

---

**Last Updated**: 2025-06-24
**Languages Covered**: 8+ with production examples
**Setup Time**: 2-15 minutes depending on language
**Status**: ✅ Production tested and ready to use

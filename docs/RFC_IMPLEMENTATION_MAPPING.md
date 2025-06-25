# Mapeamento de RFCs para Implementação do Projeto LDAP Core Shared

Este documento serve como guia de referência para correlacionar as especificações RFC disponíveis na pasta `docs/` com as funcionalidades que devem ser implementadas no projeto `ldap-core-shared`.

## 📋 Índice

1. [RFCs Core (Especificações Fundamentais)](#rfcs-core)
2. [RFCs de Schema](#rfcs-de-schema)
3. [RFCs de Controles e Extensões](#rfcs-de-controles-e-extensões)
4. [RFCs de LDIF](#rfcs-de-ldif)
5. [RFCs Informacionais](#rfcs-informacionais)
6. [RFCs Experimentais](#rfcs-experimentais)
7. [Mapeamento por Módulo do Projeto](#mapeamento-por-módulo)

---

## 🎯 RFCs Core (Especificações Fundamentais)

### RFC 4510-4519 - Especificações LDAP v3

| RFC      | Título                           | Módulo Implementação                                 | Prioridade | Descrição                            |
| -------- | -------------------------------- | ---------------------------------------------------- | ---------- | ------------------------------------ |
| RFC 4510 | Technical Specification Road Map | `core/__init__.py`                                   | 🔴 CRÍTICA | Visão geral das especificações LDAP  |
| RFC 4511 | The Protocol                     | `core/operations.py`<br>`core/connection_manager.py` | 🔴 CRÍTICA | Operações do protocolo LDAP          |
| RFC 4512 | Directory Information Models     | `domain/models.py`<br>`schema/parser.py`             | 🔴 CRÍTICA | Modelos de informação do diretório   |
| RFC 4513 | Authentication Methods           | `core/security.py`                                   | 🔴 CRÍTICA | Métodos de autenticação e segurança  |
| RFC 4514 | DN String Representation         | `utils/dn_utils.py`<br>`utils/simple_dn_utils.py`    | 🔴 CRÍTICA | Representação string de DNs          |
| RFC 4515 | Search Filters                   | `core/search_engine.py`<br>`utils/ldap_helpers.py`   | 🔴 CRÍTICA | Filtros de busca LDAP                |
| RFC 4516 | LDAP URL                         | `utils/ldap_helpers.py`                              | 🟡 MÉDIA   | URLs LDAP                            |
| RFC 4517 | Syntaxes and Matching Rules      | `schema/validator.py`<br>`schema/parser.py`          | 🔴 CRÍTICA | Sintaxes e regras de comparação      |
| RFC 4518 | Internationalized Strings        | `utils/ldap_helpers.py`                              | 🟡 MÉDIA   | Preparação de strings internacionais |
| RFC 4519 | Schema for User Applications     | `schema/discovery.py`<br>`schema/parser.py`          | 🔴 CRÍTICA | Schema padrão para aplicações        |

---

## 🗂️ RFCs de Schema

### Definições de Schema e Objetos

| RFC      | Título                             | Módulo Implementação                           | Prioridade | Funcionalidades                                                                          |
| -------- | ---------------------------------- | ---------------------------------------------- | ---------- | ---------------------------------------------------------------------------------------- |
| RFC 2247 | Using Domains in LDAP/X.500 DNs    | `utils/dn_utils.py`<br>`schema/parser.py`      | 🟡 MÉDIA   | - Estrutura DN baseada em domínios<br>- Validação de domínios<br>- Conversão de domínios |
| RFC 2798 | inetOrgPerson Object Class         | `schema/discovery.py`<br>`schema/parser.py`    | 🟠 ALTA    | - Classe inetOrgPerson<br>- Atributos pessoais<br>- Validação de pessoas                 |
| RFC 2926 | LDAP Schemas to/from SLP Templates | `schema/migrator.py`<br>`schema/comparator.py` | 🔵 BAIXA   | - Conversão de schemas<br>- Templates SLP                                                |
| RFC 3045 | Storing Vendor Information         | `schema/discovery.py`                          | 🔵 BAIXA   | - Informações do fabricante<br>- Root DSE vendor attributes                              |
| RFC 3112 | Authentication Password Schema     | `core/security.py`<br>`schema/parser.py`       | 🟠 ALTA    | - Schema de senhas<br>- Autenticação de usuários                                         |
| RFC 3687 | Component Matching Rules           | `schema/validator.py`                          | 🟡 MÉDIA   | - Regras de matching de componentes<br>- Validação avançada                              |
| RFC 3698 | Additional Matching Rules          | `schema/validator.py`                          | 🟡 MÉDIA   | - Regras de matching estendidas                                                          |
| RFC 4523 | X.509 Certificates Schema          | `schema/parser.py`                             | 🟡 MÉDIA   | - Schema para certificados X.509<br>- Validação de certificados                          |
| RFC 4524 | COSINE LDAP/X.500 Schema           | `schema/parser.py`                             | 🟡 MÉDIA   | - Elementos schema COSINE<br>- Atributos organizacionais                                 |
| RFC 4530 | entryUUID Operational Attribute    | `schema/parser.py`<br>`domain/models.py`       | 🟠 ALTA    | - Atributo operacional entryUUID<br>- Identificação única de entradas                    |
| RFC 5020 | entryDN Operational Attribute      | `schema/parser.py`<br>`domain/models.py`       | 🟠 ALTA    | - Atributo operacional entryDN<br>- DN da entrada                                        |

---

## 🎛️ RFCs de Controles e Extensões

### Controles LDAP e Operações Estendidas

| RFC      | Título                             | Módulo Implementação                          | Prioridade | Funcionalidades                                                   |
| -------- | ---------------------------------- | --------------------------------------------- | ---------- | ----------------------------------------------------------------- |
| RFC 2589 | Dynamic Directory Services         | `core/operations.py`                          | 🔵 BAIXA   | - Serviços de diretório dinâmicos<br>- Entradas temporárias       |
| RFC 2696 | Simple Paged Results Control       | `core/search_engine.py`                       | 🟠 ALTA    | - Controle de resultados paginados<br>- Busca com paginação       |
| RFC 2891 | Server Side Sorting Control        | `core/search_engine.py`                       | 🟠 ALTA    | - Ordenação no servidor<br>- Controle de sort                     |
| RFC 3062 | Password Modify Extended Operation | `core/operations.py`<br>`core/security.py`    | 🟠 ALTA    | - Operação estendida de mudança de senha<br>- Gestão de senhas    |
| RFC 3296 | Named Subordinate References       | `core/operations.py`                          | 🟡 MÉDIA   | - Referências subordinadas nomeadas<br>- Gestão de referrals      |
| RFC 3671 | Collective Attributes              | `schema/parser.py`<br>`core/operations.py`    | 🟡 MÉDIA   | - Atributos coletivos<br>- Herança de atributos                   |
| RFC 3672 | Subentries                         | `schema/discovery.py`<br>`core/operations.py` | 🟡 MÉDIA   | - Subentradas administrativas<br>- Gestão de políticas            |
| RFC 3829 | Authorization Identity Controls    | `core/security.py`                            | 🟡 MÉDIA   | - Controles de identidade de autorização<br>- Proxy authorization |
| RFC 3876 | Returning Matched Values           | `core/search_engine.py`                       | 🟡 MÉDIA   | - Controle de valores correspondentes<br>- Filtros de atributos   |
| RFC 3909 | Cancel Operation                   | `core/operations.py`                          | 🟡 MÉDIA   | - Cancelamento de operações<br>- Controle de tempo                |
| RFC 4370 | Proxied Authorization Control      | `core/security.py`                            | 🟡 MÉDIA   | - Controle de autorização por proxy<br>- Delegação de identidade  |
| RFC 4527 | Read Entry Controls                | `core/operations.py`                          | 🟡 MÉDIA   | - Controles de leitura de entrada<br>- Pre/post read controls     |
| RFC 4528 | Assertion Control                  | `core/operations.py`                          | 🟡 MÉDIA   | - Controle de asserção<br>- Operações condicionais                |
| RFC 4531 | Turn Operation                     | `core/operations.py`                          | 🔵 BAIXA   | - Operação de inversão de papel<br>- Controle de conexão          |
| RFC 4532 | "Who am I?" Operation              | `core/security.py`                            | 🟡 MÉDIA   | - Operação de identificação<br>- Descoberta de identidade         |
| RFC 4533 | Content Synchronization            | `core/operations.py`                          | 🟠 ALTA    | - Sincronização de conteúdo<br>- Replicação de dados              |
| RFC 5805 | Transactions                       | `core/operations.py`                          | 🟠 ALTA    | - Suporte a transações<br>- Operações atômicas                    |
| RFC 6171 | Don't Use Copy Control             | `core/operations.py`                          | 🔵 BAIXA   | - Controle anti-cópia<br>- Restrições de operação                 |

---

## 📄 RFCs de LDIF

### Formato de Intercâmbio de Dados LDAP

| RFC      | Título                       | Módulo Implementação                                                                                                              | Prioridade | Funcionalidades                                                                                                                                                  |
| -------- | ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| RFC 2849 | LDAP Data Interchange Format | `ldif/processor.py`<br>`ldif/writer.py`<br>`ldif/validator.py`<br>`ldif/analyzer.py`<br>`ldif/transformer.py`<br>`ldif/merger.py` | 🔴 CRÍTICA | - Parser LDIF completo<br>- Escritor LDIF avançado<br>- Validação de formato<br>- Análise de conteúdo<br>- Transformação de entradas<br>- Fusão de arquivos LDIF |

---

## 🎯 Prioridades de Implementação

### 🔴 CRÍTICA (Implementar Primeiro)

1. **Core LDAP Protocol** (RFC 4511, 4512, 4513, 4514, 4515, 4517, 4519)
2. **LDIF Processing** (RFC 2849)
3. **Connection Management** com pools empresariais
4. **Basic Operations** (search, add, modify, delete)

### 🟠 ALTA (Segunda Fase)

1. **Advanced Controls** (paginação, ordenação, transações)
2. **Schema Management** avançado
3. **Security Features** (SSH tunnels, SASL)
4. **Performance Monitoring**

### 🟡 MÉDIA (Terceira Fase)

1. **Extended Operations**
2. **Advanced Schema Features**
3. **Internationalization**
4. **Additional Controls**

### 🔵 BAIXA (Futuras Releases)

1. **Experimental Features**
2. **Specialized Schemas**
3. **Legacy Support**

---

**Última Atualização**: $(date)
**Versão do Documento**: 1.0
**Total de RFCs Mapeados**: 65+ RFCs

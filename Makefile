# flext-ldap - LDAP Operations Library
PROJECT_NAME := flext-ldap
include ../base.mk

# === PROJECT-SPECIFIC TARGETS ===
.PHONY: ldap-start ldap-stop ldap-restart ldap-health ldap-reset
.PHONY: ldap-search ldap-search-users ldap-search-groups ldap-shell ldap-logs
.PHONY: test-unit test-integration build docs docs-serve shell

# Docker LDAP server management
ldap-start: ## Start Docker LDAP server
	$(Q)docker-compose -f ../docker/docker-compose.openldap.yml up -d

ldap-stop: ## Stop Docker LDAP server
	$(Q)docker-compose -f ../docker/docker-compose.openldap.yml down

ldap-restart: ldap-stop ldap-start ## Restart LDAP server

ldap-health: ## Check LDAP server health
	$(Q)docker-compose -f ../docker/docker-compose.openldap.yml ps

ldap-reset: ## Reset LDAP server (clean data)
	$(Q)docker-compose -f ../docker/docker-compose.openldap.yml down -v
	$(Q)docker-compose -f ../docker/docker-compose.openldap.yml up -d

ldap-search: ## Search LDAP directory
	$(Q)docker exec ldap-server ldapsearch -x -H ldap://localhost -b "dc=example,dc=com"

ldap-search-users: ## Search LDAP users
	$(Q)docker exec ldap-server ldapsearch -x -H ldap://localhost -b "ou=users,dc=example,dc=com"

ldap-search-groups: ## Search LDAP groups
	$(Q)docker exec ldap-server ldapsearch -x -H ldap://localhost -b "ou=groups,dc=example,dc=com"

ldap-shell: ## Open LDAP container shell
	$(Q)docker exec -it ldap-server /bin/bash

ldap-logs: ## View LDAP server logs
	$(Q)docker-compose -f ../docker/docker-compose.openldap.yml logs -f

docs: ## Build documentation
	$(Q)$(POETRY) run mkdocs build

docs-serve: ## Serve documentation
	$(Q)$(POETRY) run mkdocs serve

.DEFAULT_GOAL := help

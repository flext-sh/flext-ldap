# Private project handlers for flext-ldap.
# Strict extension: only `_custom_<verb>_<what>` handlers and `(pre|post)-<verb>[-<what>]`
# hooks. Public targets, toolchain vars, .DEFAULT_GOAL, includes, and help are
# invalid (base.mk owns those). Each handler maps to `make <verb> WHAT=<what>`.
.PHONY: _custom_run_ldap-start _custom_run_ldap-stop _custom_run_ldap-restart _custom_run_ldap-health _custom_run_ldap-reset _custom_run_ldap-logs _custom_run_ldap-shell
_custom_run_ldap-start: ## make run WHAT=ldap-start — start Docker LDAP server
	$(Q)docker-compose -f ../docker/docker-compose.openldap.yml up -d
_custom_run_ldap-stop: ## make run WHAT=ldap-stop — stop Docker LDAP server
	$(Q)docker-compose -f ../docker/docker-compose.openldap.yml down
_custom_run_ldap-restart: ## make run WHAT=ldap-restart — restart Docker LDAP server
	$(Q)docker-compose -f ../docker/docker-compose.openldap.yml down
	$(Q)docker-compose -f ../docker/docker-compose.openldap.yml up -d
_custom_run_ldap-health: ## make run WHAT=ldap-health — Docker LDAP server status
	$(Q)docker-compose -f ../docker/docker-compose.openldap.yml ps
_custom_run_ldap-reset: ## make run WHAT=ldap-reset — reset Docker LDAP server (clean data)
	$(Q)docker-compose -f ../docker/docker-compose.openldap.yml down -v
	$(Q)docker-compose -f ../docker/docker-compose.openldap.yml up -d
_custom_run_ldap-logs: ## make run WHAT=ldap-logs — tail Docker LDAP server logs
	$(Q)docker-compose -f ../docker/docker-compose.openldap.yml logs -f
_custom_run_ldap-shell: ## make run WHAT=ldap-shell — open LDAP container shell
	$(Q)docker exec -it ldap-server /bin/bash

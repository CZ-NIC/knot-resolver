
client: client/kresc
	@# Install luarocks modules because I do not know how to do it properly
	@# TODO: try to detect this somehow
	@echo "make sure ljlinenoise is installed, e.g. via:"
	@echo "$ luarocks install ljlinenoise --local"

client/kresc: client/kresc.lua.in
	@$(call quiet,SED,$<) -e "s/@libkres_SONAME@/$(libkres_SONAME)/" $< > $@

client-install: client
	$(INSTALL) -D client/kresc $(DESTDIR)$(SBINDIR)

client-clean:
	@$(call quiet,RM,client/kresc) client/kresc

.PHONY: client client-install client-clean


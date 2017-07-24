client_SOURCES := kresc.lua

client:
	# Install luarocks modules because I do not know how to do it properly
	luarocks install ljlinenoise --local;

client/kresc.lua: client/kresc.lua.in
	@$(call quiet,SED,$<) -e "s/@libkres_SONAME@/$(libkres_SONAME)/" $< > $@
	
client-clean:
	@$(call quiet,RM,modules/version/version.lua) client/client.lua
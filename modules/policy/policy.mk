AHOCORASICK_DIR = modules/policy/lua-aho-corasick/

policy_SOURCES := policy.lua
policy_DEPEND := $(AHOCORASICK_DIR)ahocorasick$(LIBEXT)
$(call make_lua_module,policy)

policy-clean:
	$(MAKE) -C $(AHOCORASICK_DIR) clean
$(AHOCORASICK_DIR)ahocorasick$(LIBEXT): $(AHOCORASICK_DIR)Makefile
	$(MAKE) -C $(AHOCORASICK_DIR) ahocorasick$(LIBEXT) CXXFLAGS="$(lua_CFLAGS)"

policy-install: ahocorasick-install
ahocorasick-install: $(AHOCORASICK_DIR)ahocorasick$(LIBEXT) $(DESTDIR)$(MODULEDIR)
	$(INSTALL) -m 755 $(AHOCORASICK_DIR)ahocorasick$(LIBEXT) $(DESTDIR)$(MODULEDIR)


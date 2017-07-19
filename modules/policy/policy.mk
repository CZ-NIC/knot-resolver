policy_SOURCES := policy.lua lua-aho-corasick/ahocorasick.so
policy_DEPEND := modules/policy/lua-aho-corasick/ahocorasick.so
$(call make_lua_module,policy)

AHOCORASICK_DIR = modules/policy/lua-aho-corasick/
policy-clean:
	$(MAKE) -C $(AHOCORASICK_DIR) clean
$(AHOCORASICK_DIR)ahocorasick.so: $(AHOCORASICK_DIR)Makefile
	$(MAKE) -C $(AHOCORASICK_DIR) MY_CFLAGS=$(lua_CFLAGS) SO_EXT=so
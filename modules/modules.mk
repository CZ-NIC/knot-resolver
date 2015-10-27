# List of built-in modules
modules_TARGETS := hints \
                   stats \
                   cachectl

# Memcached
ifeq ($(HAS_libmemcached),yes)
modules_TARGETS += kmemcached
endif
# Redis
ifeq ($(HAS_hiredis),yes)
modules_TARGETS += redis
endif

# List of Lua modules
ifeq ($(HAS_lua),yes)
modules_TARGETS += ketcd \
                   graphite \
                   policy \
                   view \
                   predict \
                   dns64
endif

# List of Golang modules
ifeq ($(HAS_go),yes)
ifeq ($(HAS_geoip),yes)
modules_TARGETS += tinyweb
endif
endif

# Make C module
define make_c_module
$(eval $(call make_module,$(1),modules/$(1)))
endef

# Make Lua module
define make_lua_module
$(eval $(call lua_target,$(1),modules/$(1)))
endef

# Lua target definition
define lua_target
$(1) := $$(addprefix $(2)/,$$($(1)_SOURCES))
$(1)-clean:
$(1)-install: $$(addprefix $(2)/,$$($(1)_SOURCES))
	$(INSTALL) -d $(PREFIX)/$(MODULEDIR)
	$(INSTALL) $$^ $(PREFIX)/$(MODULEDIR)
.PHONY: $(1) $(1)-install $(1)-clean
endef

# Make Go module
define make_go_module
$(eval $(call go_target,$(1),modules/$(1)))
endef

# Go target definition
define go_target 
$(1) := $(2)/$(1)$(LIBEXT)
$(2)/$(1)$(LIBEXT): $$($(1)_SOURCES) $$($(1)_DEPEND)
	@echo "  GO	$(2)"; CGO_CFLAGS="$(BUILD_CFLAGS)" CGO_LDFLAGS="$$($(1)_LIBS)" $(GO) build -buildmode=c-shared -o $$@ $$($(1)_SOURCES)
$(1)-clean:
	$(RM) -r $(2)/$(1).h $(2)/$(1)$(LIBEXT)
ifeq ($$(strip $$($(1)_INSTALL)),)
$(1)-dist:
	$(INSTALL) -d $(PREFIX)/$(MODULEDIR)
else
$(1)-dist: $$($(1)_INSTALL)
	$(INSTALL) -d $(PREFIX)/$(MODULEDIR)/$(1)
	$(INSTALL) $$^ $(PREFIX)/$(MODULEDIR)/$(1)
endif
$(1)-install: $(2)/$(1)$(LIBEXT) $(1)-dist
	$(INSTALL) $(2)/$(1)$(LIBEXT) $(PREFIX)/$(MODULEDIR)
.PHONY: $(1)-clean $(1)-install $(1)-dist
endef

# Include modules
$(foreach module,$(modules_TARGETS),$(eval include modules/$(module)/$(module).mk))
$(eval modules = $(foreach module,$(modules_TARGETS),$$($(module))))

# Targets
modules: $(modules)
modules-clean: $(addsuffix -clean,$(modules_TARGETS))
modules-install: $(addsuffix -install,$(modules_TARGETS))

.PHONY: modules modules-clean modules-install

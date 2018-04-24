# List of built-in modules
modules_TARGETS := hints \
                   stats

# DNS cookies
ifeq ($(ENABLE_COOKIES),yes)
modules_TARGETS += cookies
endif

ifeq ($(ENABLE_DNSTAP),yes)
modules_TARGETS += dnstap
endif

# Memcached
ifeq ($(HAS_libmemcached),yes)
#modules_TARGETS += memcached
endif
# Redis
ifeq ($(HAS_hiredis),yes)
#modules_TARGETS += redis
endif

# List of Lua modules
ifeq ($(HAS_lua),yes)
modules_TARGETS += etcd \
                   ta_sentinel \
                   graphite \
                   policy \
                   view \
                   predict \
                   dns64 \
                   renumber \
                   http \
                   daf \
                   workarounds \
                   version \
                   ta_signal_query \
                   priming \
                   serve_stale \
                   detect_time_skew \
                   detect_time_jump \
                   prefill
endif

# Make C module
define make_c_module
$(1)-install: $(DESTDIR)$(MODULEDIR)
$(eval $(call make_module,$(1),modules/$(1)))
endef

# Make Lua module
define make_lua_module
$(eval $(call lua_target,$(1),modules/$(1)))
endef

# Lua target definition
define lua_target
$(1) := $(1) $$(addprefix $(2)/,$$($(1)_SOURCES))
$(1) : $$($(1)_DEPEND)
$(1)-clean:
ifeq ($$(strip $$($(1)_INSTALL)),)
$(1)-dist:
	$(INSTALL) -d $(DESTDIR)$(MODULEDIR)
else
$(1)-dist: $$($(1)_INSTALL)
	$(INSTALL) -d $(DESTDIR)$(MODULEDIR)/$(1)
	$(INSTALL) -m 0644 $$^ $(DESTDIR)$(MODULEDIR)/$(1)
endif
$(1)-install: $$(addprefix $(2)/,$$($(1)_SOURCES)) $(DESTDIR)$(MODULEDIR) $(1)-dist
	$(INSTALL) -m 0644 $$(addprefix $(2)/,$$($(1)_SOURCES)) $(DESTDIR)$(MODULEDIR)
.PHONY: $(1) $(1)-install $(1)-clean $(1)-dist
endef

# Make Go module
define make_go_module
$(eval $(call go_target,$(1),modules/$(1)))
endef

# Filter CGO flags
CGO_CFLAGS := $(filter-out -flto,$(BUILD_CFLAGS))

# Go target definition
define go_target 
$(1) := $(2)/$(1)$(LIBEXT)
$(2)/$(1)$(LIBEXT): $$($(1)_SOURCES) $$($(1)_DEPEND)
	@echo "  GO	$(2)"; CGO_CFLAGS="$(CGO_CFLAGS)" CGO_LDFLAGS="$$($(1)_LIBS) $(CFLAGS)" $(GO) build -buildmode=c-shared -o $$@ $$($(1)_SOURCES)
$(1)-clean:
	$(RM) -r $(2)/$(1).h $(2)/$(1)$(LIBEXT)
ifeq ($$(strip $$($(1)_INSTALL)),)
$(1)-dist:
	$(INSTALL) -d $(DESTDIR)$(MODULEDIR)
else
$(1)-dist: $$($(1)_INSTALL)
	$(INSTALL) -d $(DESTDIR)$(MODULEDIR)/$(1)
	$(INSTALL) -m 0644 $$^ $(DESTDIR)$(MODULEDIR)/$(1)
endif
$(1)-install: $(2)/$(1)$(LIBEXT) $(1)-dist $(DESTDIR)$(MODULEDIR)
	$(INSTALL) $(2)/$(1)$(LIBEXT) $(DESTDIR)$(MODULEDIR)
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

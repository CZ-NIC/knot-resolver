# List of built-in modules
modules_TARGETS := hints

# Make C module
define make_c_module
$(eval $(call make_module,$(1),modules/$(1)))
endef

# Make Go module
define make_go_module
# TODO: compilable only with gccgo -shared
# go tool cgo -- $(CFLAGS) $$($(1)_SOURCES)
endef

# Build rules
modules: $(modules_TARGETS)
modules-clean: $(addsuffix -clean,$(modules_TARGETS))
modules-install: $(addsuffix -install,$(modules_TARGETS))
$(foreach module,$(modules_TARGETS),$(eval include modules/$(module)/$(module).mk))
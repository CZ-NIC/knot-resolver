# List of built-in modules
modules_TARGETS := hints

# List of Golang modules
$(eval $(call find_bin,gccgo))
ifeq ($(HAS_gccgo),yes)
modules_TARGETS += gostats
endif

# Make C module
define make_c_module
$(eval $(call make_module,$(1),modules/$(1)))
endef

# Go target definition
define go_target
$(1): $(2)/$(1)$(LIBEXT)
$(2)/_obj/_cgo_.o: $$($(1)_SOURCES)
	$(INSTALL) -d $(2)/_obj
	$(call quiet,CGO,$$^) -gccgo=true -objdir=$(2)/_obj -- $(CFLAGS) $$^
$(2)/_obj/$(1).o: $(2)/_obj/_cgo_.o
	$(call quiet,GCCGO,$$@) -fPIC -c $(2)/_obj/*.go
$(2)/$(1)$(LIBEXT): $(2)/_obj/$(1).o $$($(1)_DEPEND)
	$(call quiet,GCCGO,$$@) $(CFLAGS) -$(LIBTYPE) -fPIC -Wno-return-type -o $$@ $(2)/_obj/*.o $(2)/_obj/*.c -lgcc $$($(1)_LIBS)
$(1)-clean:
	$(RM) -r $(2)/_obj $(2)/$(1)$(LIBEXT)
$(1)-install: $(2)/$(1)$(LIBEXT)
	$(INSTALL) -d $(PREFIX)/$(MODULEDIR)
	$(INSTALL) $$^ $(PREFIX)/$(MODULEDIR)
.PHONY: $(1) $(1)-clean $(1)-install
endef

# Make Go module
define make_go_module
$(eval $(call go_target,$(1),modules/$(1)))
endef

# Build rules
modules: $(modules_TARGETS)
modules-clean: $(addsuffix -clean,$(modules_TARGETS))
modules-install: $(addsuffix -install,$(modules_TARGETS))
$(foreach module,$(modules_TARGETS),$(eval include modules/$(module)/$(module).mk))
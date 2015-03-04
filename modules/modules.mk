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
$(1)_OBJS := $(addprefix $(2)/_obj/,_cgo_defun.o _cgo_export.o $(subst /,_,$(2))_$(1).cgo2.o)
$(1)_GOBJS := $(addprefix $(2)/_obj/,_cgo_gotypes.go $(subst /,_,$(2))_$(1).cgo1.go)
$(2)/_obj/_cgo_export.h: $$($(1)_SOURCES)
	@$(INSTALL) -d $(2)/_obj
	$(call quiet,CGO,$$^) -gccgo=true -objdir=$(2)/_obj -- $(CFLAGS) $$^
$(2)/$(1).o: $(2)/_obj/_cgo_export.h $$($(1)_GOBJS)
	$(call quiet,GCCGO,$$@) -I$(2)/_obj -c -fPIC $$($(1)_GOBJS) -o $$@
$(2)/$(1)$(LIBEXT): $(2)/_obj/_cgo_export.h $(2)/$(1).o $$($(1)_OBJS) $$($(1)_DEPEND)
	$(call quiet,GCCGO,$$@) -g -fPIC -I$(2)/_obj $(2)/$(1).o $$($(1)_OBJS) -o $$@ -$(LIBTYPE) -lgcc -lgo $$($(1)_LIBS)
$(1): $(2)/_obj/_cgo_export.h $(2)/$(1)$(LIBEXT)
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
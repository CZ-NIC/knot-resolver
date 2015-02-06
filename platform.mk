# Platform-specific
CCLD := $(CC)
LIBEXT := .so
MODEXT := $(LIBEXT)
LIBTYPE := shared
MODTYPE := shared
BINEXT :=
PLATFORM = Linux
ifeq ($(OS),Windows_NT)
	PLATFORM := Windows
	RM := del
	LN := link
	LIBEXT := .lib
	BINEXT := .exe
else
	UNAME := $(shell uname -s)
    ifeq ($(UNAME),Darwin)
        PLATFORM := Darwin
        LIBEXT := .dylib
        MODTYPE := dynamiclib
    else
    	PLATFORM := POSIX
		LDFLAGS += -pthread
    endif
endif

# Silent compilation
ifeq ($(V),1)
	quiet = $($1)
else
	quiet = @echo "  $1	$2"; $($1)
endif	

%.o: %.c
	$(call quiet,CC,$<) $(CFLAGS) -MMD -MP -c $< -o $@

# Make objects and depends (name)
define make_objs
$(1)_OBJ := $$($(1)_SOURCES:.c=.o)
$(1)_DEP := $$($(1)_SOURCES:.c=.d)
-include $$($(1)_DEP)
endef

# Make target (name,path,ext,ldflags,dst)
define make_target
$$(eval $$(call make_objs,$(1)))
$(1): $(2)/$(1)$(3)
$(2)/$(1)$(3): $$($(1)_OBJ) $$($(1)_DEPEND)
	$(call quiet,CCLD,$$@) $(CFLAGS) $$($(1)_OBJ) -o $$@ $(4) $(LDFLAGS) $$($(1)_LIBS)
$(1)-clean:
	$(RM) $$($(1)_OBJ) $$($(1)_DEP) $(2)/$(1)$(3)
$(1)-install: $(2)/$(1)$(3)
	$(INSTALL) $$^ $(PREFIX)/$(5) 
ifneq ($$(strip $$($(1)_HEADERS)),)
	$(INSTALL) -d $(PREFIX)/$(INCLUDEDIR)/$(1)
	$(INSTALL) $$($(1)_HEADERS) $(PREFIX)/$(INCLUDEDIR)/$(1)
endif
.PHONY: $(1) $(1)-clean $(1)-install
endef

# Make targets (name,path)
make_bin = $(call make_target,$(1),$(2),$(BINEXT),,$(BINDIR))
make_lib = $(call make_target,$(1),$(2),$(LIBEXT),-$(LIBTYPE),$(LIBDIR))
make_module = $(call make_target,$(1),$(2),$(MODEXT),-$(MODTYPE),$(LIBDIR))

# Evaluate library
define have_lib
ifeq ($$(strip $$($(1)_LIBS)),)
	HAS_$(1) := no
else
	HAS_$(1) := yes
$(1):
endif
endef

# Find library (pkg-config)
define find_lib
	ifeq ($$(strip $$($(1)_LIBS)),)
		$(1)_CFLAGS := $(shell pkg-config --cflags $(1))
		$(1)_LIBS := $(shell pkg-config --libs $(1) --silence-errors)
	endif
	$(call have_lib,$(1))
endef

# Find Python 
define find_python
	python_CFLAGS := $(shell $(PYTHON) -c "from distutils import sysconfig as c;print('-I%s' % c.get_python_inc())")
	python_LIBS := $(shell $(PYTHON) -c "from distutils import sysconfig as c;print('-L%s -lpython%s' % (c.get_config_var('LIBDIR'), c.get_config_var('VERSION')))")
	$(call have_lib,python)
endef
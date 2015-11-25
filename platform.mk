# Platform-specific
CCLD := $(CC)
CGO := go tool cgo
GO := go
CAT := cat
LIBEXT := .so
MODEXT := $(LIBEXT)
AREXT  := .a
LIBTYPE := shared
MODTYPE := shared
ARTYPE  := static
BINEXT :=
PLATFORM = Linux
ARCH := $(word 1, $(subst -, ,$(shell $(CC) -dumpmachine)))
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
        LDFLAGS += -pthread -lm -Wl,-E
        ifeq (,$(findstring BSD,$(UNAME)))
            LDFLAGS += -ldl
        endif
    endif
endif

# Silent compilation
ifeq ($(V),1)
	quiet = $($1)
else
	quiet = @echo "  $1	$2"; $($1)
endif	

%.o: %.c
	$(call quiet,CC,$<) $(BUILD_CFLAGS) -MMD -MP -c $< -o $@

# Make objects and depends (name)
define make_objs
$(1)_OBJ := $$($(1)_SOURCES:.c=.o)
$(1)_DEP := $$($(1)_SOURCES:.c=.d)

-include $$($(1)_DEP)
endef

# Make target (name,path,ext,ldflags,dst,amalgable)
define make_target
ifeq ($(AMALG)|$(6), yes|yes)
$(1).amalg.c: $$($(1)_SOURCES)
	$(call quiet,CAT,$$@) $$($(1)_SOURCES) > $$@
# AR requires .o compiled
$(1)_OBJ := $(1).amalg.c
ifeq ($(4),-$(ARTYPE))
$(1)_OBJ := $(1).amalg.o
endif
else
$$(eval $$(call make_objs,$(1)))
endif
$(1) := $(2)/$(1)$(3)
$(2)/$(1)$(3): $$($(1)_OBJ) $$($(1)_DEPEND)
ifeq ($(4),-$(ARTYPE))
	$(call quiet,AR,$$@) rcs $$@ $$($(1)_OBJ)
else
	$(call quiet,CCLD,$$@) $(BUILD_CFLAGS) $$($(1)_CFLAGS) $$($(1)_OBJ) -o $$@ $(4) $$($(1)_LIBS) $(BUILD_LDFLAGS)
endif
$(1)-clean:
	$(RM) $$($(1)_OBJ) $$($(1)_DEP) $(2)/$(1)$(3) $(1).amalg.c $(1).amalg.o
$(1)-install: $(2)/$(1)$(3)
	$(INSTALL) -d $(PREFIX)/$(5)
	$(INSTALL) $$^ $(PREFIX)/$(5)
ifneq ($$(strip $$($(1)_HEADERS)),)
	$(INSTALL) -d $(PREFIX)/$(INCLUDEDIR)/$(1)
	$(INSTALL) -m 644 $$($(1)_HEADERS) $(PREFIX)/$(INCLUDEDIR)/$(1)
endif
.PHONY: $(1)-clean $(1)-install
endef

# Make targets (name,path)
make_bin = $(call make_target,$(1),$(2),$(BINEXT),$(BINFLAGS),$(BINDIR),yes)
make_lib = $(call make_target,$(1),$(2),$(LIBEXT),-$(LIBTYPE),$(LIBDIR),yes)
make_module = $(call make_target,$(1),$(2),$(LIBEXT),-$(LIBTYPE),$(MODULEDIR),no)
make_shared = $(call make_target,$(1),$(2),$(MODEXT),-$(MODTYPE),$(LIBDIR),yes)
make_static = $(call make_target,$(1),$(2),$(AREXT),-$(ARTYPE),$(LIBDIR),yes)

# Evaluate library
define have_lib
ifeq ($$(strip $$($(1)_LIBS)),)
	HAS_$(1) := no
else
	HAS_$(1) := yes
endif
endef

# Find library (pkg-config)
define find_lib
	$(call find_alt,$(1),$(1),$(2))
endef

# Find library alternative (pkg-config)
define find_alt
	ifeq ($$(strip $$($(1)_LIBS)),)
		ifneq ($(strip $(3)),)
			$(1)_VER := $(shell pkg-config --atleast-version=$(3) $(2) && echo $(3))
		endif
		ifeq ($(strip $(3)),$$($(1)_VER))
			$(1)_CFLAGS := $(shell pkg-config --cflags $(2) --silence-errors)
			$(1)_LIBS := $(shell pkg-config --libs $(2)  --silence-errors)
		endif
	endif
	$(call have_lib,$(1),$(3))
endef

# Find binary
define find_bin
	ifeq ($$(strip $$($(1)_BIN)),)
		$(1)_BIN := $(shell which $(1))
	endif
	ifeq ($$(strip $$($(1)_BIN)),)
		HAS_$(1) := no
	else
		HAS_$(1) := yes
		$(1) := $$($(1)_BIN)
	endif
endef

# Find version
define find_ver
	ifeq ($(shell test $(2) -ge $(3); echo $$?),0)
		HAS_$(1) := yes
	else
		HAS_$(1) := no
	endif
endef

# Find Go package
define find_gopkg
	HAS_$(1) := $(shell go list $(2) > /dev/null 2>&1 && echo yes || echo no)
endef


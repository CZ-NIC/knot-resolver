
bench_BIN := \
	bench_lru

# Dependencies
bench_DEPEND := $(libkres)
bench_LIBS :=  $(libkres_TARGET) $(libkres_LIBS)

# Platform-specific library injection
ifeq ($(PLATFORM),Darwin)
	preload_syms := DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_LIBRARY_PATH="$(DYLD_LIBRARY_PATH):$(abspath lib)"
else
	preload_syms := LD_LIBRARY_PATH="$(LD_LIBRARY_PATH):$(abspath lib)"
endif

# Make bench binaries
define make_bench
$(1)_CFLAGS := -fPIC
$(1)_SOURCES := bench/$(1).c
$(1)_LIBS := $(bench_LIBS)
$(1)_DEPEND := $(bench_DEPEND)
$(call make_bin,$(1),bench)
.PHONY: $(1)
endef

$(foreach bench,$(bench_BIN),$(eval $(call make_bench,$(bench))))


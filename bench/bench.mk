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
$(1)_CFLAGS := -fPIE
$(1)_SOURCES := bench/$(1).c
$(1)_LIBS := $(bench_LIBS)
$(1)_DEPEND := $(bench_DEPEND)
$(call make_bin,$(1),bench)
endef

$(foreach bench,$(bench_BIN),$(eval $(call make_bench,$(bench))))

# Targets
.PHONY: bench bench-clean
bench-clean: $(foreach bench,$(bench_BIN),$(bench)-clean)
bench: $(foreach bench,$(bench_BIN),bench/$(bench))
	# Test LRU with increasing overfill, misses should increase ~ linearly
	@./bench/bench_lru 22 bench/bench_lru_set1.tsv - 65536 # fill = 1
	@./bench/bench_lru 23 bench/bench_lru_set1.tsv - 32768 # fill = 2
	@./bench/bench_lru 23 bench/bench_lru_set1.tsv - 16384 # fill = 4
	@./bench/bench_lru 23 bench/bench_lru_set1.tsv - 8192  # fill = 8
	@./bench/bench_lru 23 bench/bench_lru_set1.tsv - 4096  # fill = 16
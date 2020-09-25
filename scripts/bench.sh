#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -o errexit -o nounset

# Run benchmark
cd "${MESON_SOURCE_ROOT}"

echo "Test LRU with increasing overfill, misses should increase ~ linearly"

for num in 65536 32768 16384 8192 4096; do
    "${MESON_BUILD_ROOT}/${MESON_SUBDIR}/bench_lru" 23 "${MESON_SOURCE_ROOT}/${MESON_SUBDIR}/bench_lru_set1.tsv" - "${num}"
done

# SPDX-License-Identifier: GPL-3.0-or-later
# rate limiting code

kresd_src += files([
  'api.c',
  'kru-generic.c',
  'kru-avx2.c',
  '../../contrib/openbsd/siphash.c',
])

kresd_deps += [
  # https://mesonbuild.com/howtox.html#add-math-library-lm-portably
  (meson.get_compiler('c').find_library('m', required : false))
]

unit_tests += [
  ['rrl', files('tests.c', 'kru-generic.c', 'kru-avx2.c', '../../contrib/openbsd/siphash.c') + libkres_src ]
]

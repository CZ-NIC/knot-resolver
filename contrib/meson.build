# contrib
# SPDX-License-Identifier: GPL-3.0-or-later

contrib_src = files([
  'ccan/asprintf/asprintf.c',
  'ccan/json/json.c',
  'ucw/mempool.c',
  'ucw/mempool-fmt.c',
  'mempattern.c',
  'murmurhash3/murmurhash3.c',
  'base32hex.c',
  'base64.c',
  'base64url.c'
])

contrib_inc = include_directories('.', '..')

contrib_lib = static_library(
  'contrib',
  contrib_src,
  include_directories: contrib_inc,
  dependencies: libknot,
)

contrib_dep = declare_dependency(
  include_directories: contrib_inc,
  link_with: contrib_lib,
)

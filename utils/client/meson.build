# client
# SPDX-License-Identifier: GPL-3.0-or-later

kresc_src = files([
  'kresc.c',
])
c_src_lint += kresc_src

build_client = false
if get_option('client') != 'disabled'
  message('--- client dependencies ---')
  libedit = dependency('libedit', required: false)
  if libedit.found()
    build_client = true
  else  # darwin workaround: missing pkgconfig
    libedit = meson.get_compiler('c').find_library(
      'edit', required: get_option('client') == 'enabled')
    if libedit.found()
      build_client = true
    endif
  endif
  message('---------------------------')
endif


if build_client
  kresc = executable(
    'kresc',
    kresc_src,
    dependencies: [
      contrib_dep,
      libedit,
    ],
    install: true,
    install_dir: get_option('sbindir'),
  )
endif

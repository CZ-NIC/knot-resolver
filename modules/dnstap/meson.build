# C module: dnstap
# SPDX-License-Identifier: GPL-3.0-or-later

dnstap_src = files([
  'dnstap.c',
])

## dnstap dependencies
build_dnstap = false
if get_option('dnstap') != 'disabled'
  dnstap_required = get_option('dnstap') == 'enabled'
  message('--- dnstap module dependencies ---')
  libprotobuf_c = dependency('libprotobuf-c', version: '>=1', required: dnstap_required)
  libfstrm = dependency('libfstrm', version: '>=0.2', required: dnstap_required)
  protoc_c = find_program('protoc-c', required: dnstap_required)
  message('----------------------------------')
  if libprotobuf_c.found() and libfstrm.found() and protoc_c.found()
    build_dnstap = true
  endif
endif


if build_dnstap
  c_src_lint += dnstap_src

  # generate protobuf-c sources using protoc-c
  dnstap_pb = custom_target(
    'dnstap_pb',
    command: [
      protoc_c,
      '--c_out=' + meson.current_build_dir(),
      '--proto_path', meson.current_source_dir(),
      meson.current_source_dir() / 'dnstap.proto',
    ],
    output: [
      'dnstap.pb-c.h',
      'dnstap.pb-c.c',
    ],
  )

  # build dnstap module
  dnstap_mod = shared_module(
    'dnstap',
    dnstap_src,
    dependencies: [
      declare_dependency(sources: dnstap_pb),
      libfstrm,
      libprotobuf_c,
    ],
    include_directories: mod_inc_dir,
    name_prefix: '',
    install: true,
    install_dir: modules_dir,
  )
endif

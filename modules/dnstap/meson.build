# C module: dnstap

dnstap_src = [
  'dnstap.c',
]

## dnstap dependencies
message('--- dnstap module dependencies ---')
libprotobuf_c = dependency('libprotobuf-c', version: '>=1', required: false)
libfstrm = dependency('libfstrm', version: '>=0.2', required: false)
protoc_c = find_program('protoc-c', required: false)
message('----------------------------------')


# build dnstap if deps are found
if libprotobuf_c.found() and libfstrm.found() and protoc_c.found()
  # generate protobuf-c sources using protoc-c
  dnstap_pb = custom_target(
    'dnstap_pb',
    command: [
      protoc_c,
      '--c_out=@OUTDIR@',
      '--proto_path', meson.current_source_dir(),
      'dnstap.proto',
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
    dnstap_pb[1],
    dependencies: [
      contrib_dep,
      libkres_dep,
      libfstrm,
      libprotobuf_c,
    ],
    name_prefix: '',
    c_args: c_args,
    install: true,
    install_dir: modules_dir,
  )
endif

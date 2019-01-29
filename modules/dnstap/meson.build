dnstap_src = [
  'dnstap.c',
]

## dnstap dependencies
libprotobuf_c = dependency('libprotobuf-c', version: '>=1', required: false)
libfstrm = dependency('libfstrm', version: '>=0.2', required: false)
protoc_c = find_program('protoc-c', required: false)


# build dnstap if deps are found
if not libprotobuf_c.found() or not libfstrm.found() or not protoc_c.found()
  message('dnstap module: skipping build')
else
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
    dnstap_pb,
    dependencies: [
      contrib_dep,
      libkres_dep,
      libfstrm,
      libprotobuf_c,
    ],
    name_prefix: '',
    install: true,
    install_dir: modules_dir,
  )
endif

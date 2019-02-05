# client

kresc_src = [
  'kresc.c',
]

message('--- kresc dependencies ---')
libedit = dependency('libedit', required: false)
if not libedit.found()
  # TODO why call find_library? osx workaround?
  libedit = meson.get_compiler('c').find_library('edit')
endif
message('--------------------------')


# build
kresc = executable(
  'kresc',
  kresc_src,
  dependencies: [
    contrib_dep,
    libkres_dep,
    libedit,
  ],
  install: true,
  install_dir: get_option('sbindir'),
)

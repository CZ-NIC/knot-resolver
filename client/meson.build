kresc_src = [
  'kresc.c',
]

if get_option('client')

  # client dependencies
  libedit = dependency('libedit', required: false)
  if not libedit.found()
    # TODO why call find_library? osx workaround?
    libedit = meson.get_compiler('c').find_library('edit')
  endif


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
endif

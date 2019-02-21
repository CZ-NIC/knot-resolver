# client

kresc_src = files([
  'kresc.c',
])
c_src_lint += kresc_src

build_client = false
if not get_option('client').disabled()
  message('--- client dependencies ---')
  libedit = dependency('libedit', required: false)
  if libedit.found()
    build_client = true
  else
    # fallback lib
    # TODO why call find_library? osx workaround?
    libedit = meson.get_compiler('c').find_library('edit', required: get_option('client'))
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
      libkres_dep,
      libedit,
    ],
    install: true,
    install_dir: get_option('sbindir'),
  )
endif

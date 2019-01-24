kresc_src = [
  'kresc.c',
]


# client dependencies
skip_client = false

libedit = dependency('libedit', required: false)
if not libedit.found()
  # TODO why call find_library? osx workaround?
  libedit = meson.get_compiler('c').find_library('edit', required: false)
  if not libedit.found()
    skip_client = true
    message('kresc client: libedit not found')
  endif
endif


# build
if skip_client
  warning('kresc client: skipping build')
else
  kresc = executable(
    'kresc',
    kresc_src,
    dependencies: [
      contrib_dep,
      libkres_dep,
      libedit,
    ],
    install: true,
    install_dir: 'sbin',
  )
endif

libedit = dependency('libedit', required: false)
if not libedit.found()
  # TODO why call find_library? osx workaround?
  libedit = meson.get_compiler('c').find_library('edit', required: false)
endif

if not libedit.found()
  warning('kresc build skipped: missing libedit')
else

  kresc_src = [
    'kresc.c',
  ]

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

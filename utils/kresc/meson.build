# kresctl

kresc_src = files([
  'main.c',
  'interactive.c',
  'process.c',
  'commands.c',
])

build_kresc = false
if get_option('sysrepo') != 'disabled'
  sysrepo_required = get_option('sysrepo') == 'enabled'
  message('--- kres client dependencies ---')
  libsysrepo = dependency('libsysrepo', version: '>=1', required: sysrepo_required and build_utils)
  libyang = dependency('libyang', version: '>=1', required: sysrepo_required and build_utils)
  libedit = meson.get_compiler('c').find_library(
      'edit', required: sysrepo_required and build_utils)
  message('----------------------------------')
  if libsysrepo.found() and libyang.found() and libedit.found()
    build_kresc = true
  endif
endif

if build_kresc
  c_src_lint += kresc_src

  kresc = executable(
    'kresc',
    kresc_src,
    dependencies: [
      contrib_dep,
      common_dep,
      libsysrepo,
      libyang,
      libedit,
    ],
    install: true,
    install_dir: get_option('sbindir'),
  )
endif

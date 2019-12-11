# utils/watcher

watcher_src = files([
  'main.c',
])

build_watcher = false
if get_option('sysrepo') != 'disabled'
  sysrepo_required = get_option('sysrepo') == 'enabled'
  message('--- kres-watcher dependencies ---')
  libsysrepo = dependency('libsysrepo', version: '>=1', required: sysrepo_required)
  libyang = dependency('libyang', version: '>=1', required: sysrepo_required)
  message('----------------------------------')
  if libsysrepo.found() and libyang.found()
    build_watcher = true
  endif
endif

if build_watcher
  c_src_lint += watcher_src

  watcher = executable(
    'kres-watcher',
    watcher_src,
    dependencies: [
      common_dep,
      libyang,
      libsysrepo
    ],
    install: true,
    install_dir: get_option('sbindir'),
  )
endif

kresctl_src = files([
    'main.c',
    'process.c',
    'interactive.c',
    'commands.c',
    'deps/lookup.c',
    'deps/mempattern.c',
    'deps/string.c',
    'deps/mempattern.c',
])
c_src_lint += kresctl_src

message('--- kresctl dependencies ---')
libedit = dependency('libedit', required: false)

if build_sysrepo and libedit.found()
  kresctl = executable(
    'kresctl',
    kresctl_src,
    sysrepo_common_src,
    dependencies: [
      contrib_dep,
      libkres_dep,
      libedit,
      libyang,
      libsysrepo,
      libknot,
    ],
    install: true,
    install_dir: get_option('sbindir'),
  )
endif
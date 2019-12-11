# utils/common

common_src = files([
  'sysrepo_conf.c',
  'string_helper.c'
])

build_common = false
if get_option('sysrepo') != 'disabled'
  sysrepo_required = get_option('sysrepo') == 'enabled'
  message('--- utils-common dependencies ---')
  libsysrepo = dependency('libsysrepo', version: '>=1', required: sysrepo_required)
  libyang = dependency('libyang', version: '>=1', required: sysrepo_required)
  message('----------------------------------')
  if libsysrepo.found() and libyang.found()
    build_common = true
  endif
endif

if build_common
  c_src_lint += common_src

  common_inc = include_directories('..')

  common_lib = library(
    'utils-common',
    common_src,
    include_directories: common_inc,
    dependencies: [
      contrib_dep,
      libyang, 
      libsysrepo,
      ]
  )

  common_dep = declare_dependency(
    include_directories: common_inc,
    link_with: common_lib,
  )
endif

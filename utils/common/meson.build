# utils/common

common_src = files([
  'sysrepo_conf.c',
  'string_helper.c'
])
c_src_lint += common_src

libsysrepo = dependency('libsysrepo', version: '>=1')
libyang = dependency('libyang', version: '>=1')

common_inc = include_directories('..')

common_lib = library(
  'utils-common',
  common_src,
  include_directories: common_inc,
  dependencies: [
    libyang, 
    libsysrepo,
    ]
)

common_dep = declare_dependency(
  include_directories: common_inc,
  link_with: common_lib,
)
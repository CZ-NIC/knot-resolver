# C module: sysrepo

sysrepo_src = files([
    'sysrepo.c',
])
c_src_lint += sysrepo_src

sysrepo_common_src = files([
    'common/sysrepo_conf.c',
    'common/sysrepo_conf.h',
	'common/helpers.h',
	'common/helpers.c',
])
c_src_lint += sysrepo_common_src

if build_sysrepo
    sysrepo_mod = shared_module(
	'sysrepo',
	sysrepo_src,
    sysrepo_common_src,
	dependencies: [
	  luajit_inc,
	  libyang,
      libsysrepo,
	],
	include_directories: mod_inc_dir,
	name_prefix: '',
	install: true,
	install_dir: modules_dir,
  )
endif
# lua module: sysrepo-lua

sysrepo_lua_src = files([
  'ffi.lua',
  'init.lua',
])

sysrepo_src = files([
  'cbindings/sysrepo_clib.h',
  'cbindings/sysrepo_clib.c',
])
c_src_lint += sysrepo_src

sysrepo_common_src = files([
	'common/sysrepo_conf.c',
	'common/sysrepo_conf.h',
	'common/string_helper.h',
	'common/string_helper.c',
])
c_src_lint += sysrepo_common_src

if build_sysrepo
  install_data(
    sysrepo_lua_src,
    install_dir: modules_dir + '/sysrepo-lua',
  )

  sysrepo_mod = shared_module(
	'cbindings',
	sysrepo_src,
	dependencies: [
	  luajit_inc,
      libyang,
	  libsysrepo,
	],
	include_directories: mod_inc_dir,
	name_prefix: '',
	install: true,
	install_dir: modules_dir + '/sysrepo-lua',
  )
endif



# lua module: sysrepo-lua

lua_config = configuration_data()
lua_config.set('modules_dir', modules_dir)

ffi = configure_file(
  input: 'ffi.lua.in',
  output: 'ffi.lua',
  configuration: lua_config,
)

sysrepo_lua_src = [
  ffi,
  files('init.lua'),
  files('debug.lua'),
  files('model.lua'),
]

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
	'common/sysrepo.h',
	'common/sysrepo.c',
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



# C module: sysrepo

sysrepo_src = files([
  'sysrepo_clib.c',
])

lua_mod_src += [
  files('sysrepo_ffi.lua'),
  files('sysrepo.lua')
]

build_sysrepo = false
if get_option('sysrepo') != 'disabled'
  sysrepo_required = get_option('sysrepo') == 'enabled'
  message('--- sysrepo module dependencies ---')
  libsysrepo = dependency('libsysrepo', version: '>=1', required: sysrepo_required)
  libyang = dependency('libyang', version: '>=1', required: sysrepo_required)
  message('----------------------------------')
  if libsysrepo.found() and libyang.found()
    build_sysrepo = true
  endif
endif

if build_sysrepo
  c_src_lint += sysrepo_src

  sysrepo_mod = shared_module(
	'sysrepo_clib',
	sysrepo_src,
	dependencies: [
    common_dep,
	  luajit_inc,
	  libsysrepo,
	],
	include_directories: mod_inc_dir,
	name_prefix: '',
	install: true,
	install_dir: modules_dir,
  )
endif



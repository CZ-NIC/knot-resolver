# C module: sysrepo

sysrepo_src = files([
  'sysrepo.c',
])

build_sysrepo = false
if get_option('sysrepo') != 'disabled'
  sysrepo_required = get_option('sysrepo') == 'enabled'
  message('--- sysrepo module dependencies ---')
  libsysrepo = dependency('libsysrepo', version: '>=1', required: sysrepo_required)
  message('----------------------------------')
  if libsysrepo.found()
    build_dnstap = true
  endif
endif


if build_dnstap
  c_src_lint += sysrepo_src

  sysrepo_mod = shared_module(
	'sysrepo',
	sysrepo_src,
	dependencies: [
	  luajit_inc,
	  libsysrepo,
	],
	include_directories: mod_inc_dir,
	name_prefix: '',
	install: true,
	install_dir: modules_dir,
  )
endif



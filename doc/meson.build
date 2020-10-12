# documentation
# SPDX-License-Identifier: GPL-3.0-or-later

# man page
man_config = configuration_data()
man_config.set('version', meson.project_version())
man_config.set('date', run_command('../scripts/get-date.sh').stdout())

man_config.set('man_seealso_systemd', '')
if systemd_files == 'enabled'
  man_config.set('man_seealso_systemd', '\\fIkresd.systemd(7)\\fR, ')
endif

man_kresd = configure_file(
  input: 'kresd.8.in',
  output: 'kresd.8',
  configuration: man_config,
)
install_man(man_kresd)


# html documentation
if get_option('doc') == 'enabled'
  message('--- doc dependencies ---')
  doxygen = find_program('doxygen')
  sphinx_build = find_program('sphinx-build-3', required: false)
  if not sphinx_build.found()
    sphinx_build = find_program('sphinx-build')
  endif
  makeinfo = find_program('makeinfo', required: false)
  install_info = find_program('install-info', required: false)

  # python dependencies: breathe, sphinx_rtd_theme
  python_breathe = run_command('python3', '-c', 'import breathe')
  if python_breathe.returncode() != 0
    # some distros might use python2 sphinx
    python_breathe = run_command('python2', '-c', 'import breathe')
    if python_breathe.returncode() != 0
      error('missing doc dependency: python breathe')
    else
      python_sphinx_rtd_theme = run_command('python2', '-c', 'import sphinx_rtd_theme')
      if python_sphinx_rtd_theme.returncode() != 0
	error('missing doc dependency: python sphinx_rtd_theme')
      endif
    endif
  else
    python_sphinx_rtd_theme = run_command('python3', '-c', 'import sphinx_rtd_theme')
    if python_sphinx_rtd_theme.returncode() != 0
      error('missing doc dependency: python sphinx_rtd_theme')
    endif
  endif
  message('------------------------')

  # install html docs
  install_subdir(
    join_paths(meson.current_source_dir(), 'html'),
    install_dir: doc_dir,
  )

  if makeinfo.found() and install_info.found()
    # install info docs
    install_subdir(
      join_paths(meson.current_source_dir(), 'texinfo', '.install'),
      strip_directory: true,
      install_dir: info_dir,
    )
  endif
endif

make_doc = find_program('../scripts/make-doc.sh')
run_target(
  'doc',
  command: make_doc,
)


run_target(
  'doc-strict',
  command: [make_doc, '-W'],
)

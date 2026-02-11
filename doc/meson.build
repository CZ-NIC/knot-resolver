# documentation
# SPDX-License-Identifier: GPL-3.0-or-later

# man page
man_config = configuration_data()
man_config.set('version', meson.project_version())
man_config.set('date', run_command('../scripts/lib/get-date.sh', check: true).stdout())

man_config.set('man_seealso_systemd', '')
if systemd_legacy_units == 'enabled'
  man_config.set('man_seealso_systemd', '\\fIkresd.systemd(7)\\fR, ')
endif

man_kresd = configure_file(
  input: 'kresd.8.in',
  output: 'kresd.8',
  configuration: man_config,
)
install_man(man_kresd)

man_kresctl = configure_file(
  input: 'kresctl.8.in',
  output: 'kresctl.8',
  configuration: man_config,
)
install_man(man_kresctl)

# html and info documentation
if get_option('doc') == 'enabled'
  message('--- doc dependencies ---')
  doxygen = find_program('doxygen')
  sphinx_build = find_program('sphinx-build-3', required: false)
  if not sphinx_build.found()
    sphinx_build = find_program('sphinx-build')
  endif

  # python dependencies: breathe, sphinx_rtd_theme
  python = find_program('python3')
  python_breathe = run_command(python, '-c', 'import breathe', check: true)
  python_sphinx_rtd_theme = run_command(python, '-c', 'import sphinx_rtd_theme', check: true)

  message('------------------------')

  # install html docs
  install_subdir(
    meson.current_source_dir() / 'html',
    install_dir: doc_dir,
  )

endif


make_doc = [find_program('../scripts/meson/make-doc.sh'), '-j', 'auto']
run_target(
  'doc',
  command: make_doc,
)


run_target(
  'doc-strict',
  command: make_doc + ['-W']
)

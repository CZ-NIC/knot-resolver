# documentation
# SPDX-License-Identifier: GPL-3.0-or-later

# man page
man_config = configuration_data()
man_config.set('version', meson.project_version())
man_config.set('date', run_command('../scripts/get-date.sh', check: true).stdout())

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
  makeinfo = find_program('makeinfo', required: false)

  # python dependencies: breathe, sphinx_rtd_theme
  python_breathe = run_command('python3', '-c', 'import breathe', check: false)
  if python_breathe.returncode() != 0
    python_breathe = run_command('python2', '-c', 'import breathe', check: false)
    if python_breathe.returncode() != 0
      error('missing doc dependency: python breathe')
    endif
    python = 'python2'
  else
    python = 'python3'
  endif

  python_sphinx_rtd_theme = run_command(python, '-c', 'import sphinx_rtd_theme', check: false)
  if python_sphinx_rtd_theme.returncode() != 0
    error('missing doc dependency: python sphinx_rtd_theme')
  endif

  python_sphinx_tabs = run_command(python, '-c', 'import sphinx_tabs', check: false)
  if python_sphinx_tabs.returncode() != 0
    error('missing doc dependency: python python-sphinx-tabs')
  endif

  jsonschema2md = find_program('jsonschema2md')
  if not jsonschema2md.found()
    error('missing doc dependency: python jsonschema2md')
  endif

  jsonschemaforhumans = run_command(python, '-c', 'import json_schema_for_humans', check: false)
  if jsonschemaforhumans.returncode() != 0
    error('missing doc dependency: python json-schema-for-humans')
  endif

  message('------------------------')

  # install html docs
  install_subdir(
    meson.current_source_dir() / 'html',
    install_dir: doc_dir,
  )

  if makeinfo.found()
    # install info docs
    install_subdir(
      meson.current_source_dir() / 'texinfo' / '.install',
      strip_directory: true,
      install_dir: info_dir,
    )
  endif
endif


make_doc = find_program('../scripts/make-doc.sh')
run_target(
  'doc',
  command: make_doc
)


run_target(
  'doc-strict',
  command: [make_doc, '-W']
)

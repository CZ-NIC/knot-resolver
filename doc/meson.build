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


# html and info documentation
if get_option('doc') == 'enabled'
  message('--- doc dependencies ---')
  doxygen = find_program('doxygen')
  sphinx_build = find_program('sphinx-build-3', required: false)
  if not sphinx_build.found()
    sphinx_build = find_program('sphinx-build')
  endif
  makeinfo = find_program('makeinfo', required: false)

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
  command: make_doc,
)


run_target(
  'doc-strict',
  command: [make_doc, '-W'],
)

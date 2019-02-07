# documentation

# man page
man_config = configuration_data()
man_config.set('version', meson.project_version())
man_config.set('date', run_command('scripts/get-date.sh', check: true)
man_config.set('keyfile_default', keyfile_default)
man_config.set('modules_dir', modules_dir)

# TODO use correct systemd man page
man_config.set('man_seealso_systemd', '')
#man_config.set('man_seealso_systemd', '\\fIkresd.systemd(7)\\fR, ')

man_kresd = configure_file(
  input: 'kresd.8.in',
  output: 'kresd.8',
  configuration: man_config,
)
install_man(man_kresd)


if get_option('doc')  # doxygen + html docs
  message('--- doc dependencies ---')
  doxygen = find_program('doxygen')
  sphinx_build = find_program('sphinx-build')

  python_breathe = run_command('python3', '-c', 'import breathe')
  if python_breathe.returncode() != 0
    # some distros might use python2 sphinx
    python_breathe = run_command('python2', '-c', 'import breathe')
    if python_breathe.returncode() != 0
      error('missing doc dependency: python breathe')
    endif
  endif
  message('------------------------')

  # create doxygen in source dir
  doc_doxyxml = custom_target(
    'doxyxml doc',
    command: [
      '../scripts/doc-doxyxml.sh',
      meson.current_source_dir(),
    ],
    output: 'doxygen',
    build_always_stale: true,
    build_by_default: true,
  )

  # create html docs in build dir
  doc = custom_target(
    'html doc',
    command: [
      sphinx_build,
      '-W',
      '-b', 'html',
      meson.current_source_dir(),
      '@OUTPUT@',
    ],
    output: 'html',
    build_always_stale: true,
    build_by_default: true,
    depends: doc_doxyxml,
  )

  # install html docs
  install_subdir(
    join_paths(meson.current_build_dir(), 'html'),
    install_dir: doc_dir,
  )
endif

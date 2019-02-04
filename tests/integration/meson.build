if get_option('extra_tests')
  prepare_deckard = find_program('../../scripts/test-integration-prepare.sh')

  # deckard dependencies
  cmake = find_program('cmake')  # for libswrapper

  deckard_contrib = custom_target(
    'deckard_contrib',
    command: [
      prepare_deckard,
      '@0@'.format(join_paths(meson.current_source_dir())),
    ],
    output: 'deckard_contrib',
    build_always_stale: true,
  )

  deckard_env = environment()
  deckard_env.prepend('PATH', kresd_install_path)

  deckard_kresd_run = find_program('deckard/kresd_run.sh')
  test(
    'integration.deckard',
    deckard_kresd_run,
    env: deckard_env,
    suite: [
      'postinstall',
      'integration',
    ],
    is_parallel: false,
    timeout: 180,  # TODO
    #workdir: join_paths(meson.current_source_dir(), 'deckard'),
    depends: deckard_contrib,
    build_by_default: false,
  )
endif

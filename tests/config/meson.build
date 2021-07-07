# SPDX-License-Identifier: GPL-3.0-or-later
config_tests += [
  ['basic', files('basic.test.lua'), ['skip_asan']],
  ['cache', files('cache.test.lua'), ['skip_asan']],
  ['net', files('net.test.lua'), ['config_net']],
  ['doh2', files('doh2.test.lua')],
  ['lru', files('lru.test.lua')],
  ['tls', files('tls.test.lua')],
  ['worker', files('worker.test.lua')],
]


run_configtest = find_program('../../scripts/test-config.sh')


foreach config_test : config_tests
  # additional suites
  extra_suites = config_test.length() >= 3 ? config_test[2] : []
  # dependencies
  depends = config_test.length() >= 4 ? config_test[3] : []

  # environment variables for test
  conftest_env = environment()
  conftest_env.prepend('PATH', sbin_dir)
  conftest_env.set('KRESD_NO_LISTEN', '1')
  conftest_env.set('SOURCE_PATH', meson.current_source_dir())

  test_file_path = '@0@'.format(config_test[1][0])
  if test_file_path[0] != '/' # absolutize paths from files('path') but accept absolute
    test_file_path = meson.source_root() / test_file_path
  endif
  conftest_env.set('TEST_FILE', test_file_path)

  test(
    'config.' + config_test[0],
    run_configtest,
    args: [
      '-c', files('test.cfg'),
      '-n'
    ],
    env: conftest_env,
    suite: [
      'postinstall',
      'config',
    ] + extra_suites,
    depends: depends,
  )
endforeach

# SPDX-License-Identifier: GPL-3.0-or-later
config_tests += [
  ['basic', files('basic.test.lua')],
  ['cache', files('cache.test.lua')],
  ['net', files('net.test.lua'), ['config_net']],
  ['doh2', files('doh2.test.lua')],
  ['lru', files('lru.test.lua')],
  ['tls', files('tls.test.lua')],
  ['worker', files('worker.test.lua')],
]


run_configtest = find_program('../../scripts/meson/test-config.sh')


foreach config_test : config_tests
  # additional suites
  extra_suites = config_test.length() >= 3 ? config_test[2] : []

  # environment variables for test
  conftest_env = environment()
  conftest_env.prepend('PATH', sbin_dir)
  conftest_env.set('KRESD_NO_LISTEN', '1')
  conftest_env.set('SOURCE_PATH', meson.current_source_dir())
  if meson.version().version_compare('>=1.4')
    conftest_env.set('TEST_FILE', '@0@'.format(config_test[1][0].full_path()))
  else
    conftest_env.set('TEST_FILE', '@0@/@1@'.format(meson.source_root(), config_test[1][0]))
  endif

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
  )
endforeach

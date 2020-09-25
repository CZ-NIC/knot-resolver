# modules
# SPDX-License-Identifier: GPL-3.0-or-later

lua_mod_src = [  # add lua modules without separate meson.build
  files('detect_time_jump/detect_time_jump.lua'),
  files('detect_time_skew/detect_time_skew.lua'),
  files('dns64/dns64.lua'),
  files('etcd/etcd.lua'),
  files('graphite/graphite.lua'),
  files('predict/predict.lua'),
  files('prefill/prefill.lua'),
  files('priming/priming.lua'),
  files('rebinding/rebinding.lua'),
  files('renumber/renumber.lua'),
  files('serve_stale/serve_stale.lua'),
  files('ta_sentinel/ta_sentinel.lua'),
  files('ta_signal_query/ta_signal_query.lua'),
  files('ta_update/ta_update.lua'),
  files('watchdog/watchdog.lua'),
  files('workarounds/workarounds.lua'),
]

config_tests += [
  ['predict', files('predict/predict.test.lua')],
  ['hints', files('hints/tests/hints.test.lua'), ['skip_asan']],
  ['nsid', files('nsid/nsid.test.lua')],
  ['dns64', files('dns64/dns64.test.lua')],
  ['ta_update', files('ta_update/ta_update.test.lua'), ['snowflake']],
  ['prefill', files('prefill/prefill.test/prefill.test.lua')],
]

integr_tests += [
  ['bogus_log', join_paths(meson.current_source_dir(), 'bogus_log', 'test.integr')],
  ['daf', join_paths(meson.current_source_dir(), 'daf', 'test.integr')],
  ['rebinding', join_paths(meson.current_source_dir(), 'rebinding', 'test.integr')],
  ['serve_stale', join_paths(meson.current_source_dir(), 'serve_stale', 'test.integr')],
  # NOTE: ta_update may pass in cases when it should fail due to race conditions
  # To ensure reliability, deckard should introduce a time wait
  ['ta_update', join_paths(meson.current_source_dir(), 'ta_update', 'ta_update.test.integr')],
]


# handle more complex C/LUA modules separately
subdir('bogus_log')
# cookies module is not currently used
subdir('daf')
subdir('dnstap')
subdir('edns_keepalive')
subdir('experimental_dot_auth')
subdir('hints')
subdir('http')
subdir('nsid')
subdir('policy')
subdir('refuse_nord')
subdir('stats')
subdir('view')

# install lua modules
foreach mod : lua_mod_src
  install_data(
    mod,
    install_dir: modules_dir,
  )
endforeach

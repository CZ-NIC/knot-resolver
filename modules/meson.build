lua_src = [
  'daf/daf.lua',
  'detect_time_jump/detect_time_jump.lua',
  'detect_time_skew/detect_time_skew.lua',
  'dns64/dns64.lua',
  'etcd/etcd.lua',
  'experimental_dot_auth/experimental_dot_auth.lua',
  'experimental_dot_auth/basexx.lua',
  'graphite/graphite.lua',
  'http/http.lua',
  'http/http_trace.lua',
  'http/prometheus.lua',
  'policy/policy.lua',
  'predict/predict.lua',
  'prefill/prefill.lua',
  'priming/priming.lua',
  'rebinding/rebinding.lua',
  'renumber/renumber.lua',
  'serve_stale/serve_stale.lua',
  'ta_sentinel/ta_sentinel.lua',
  'ta_signal_query/ta_signal_query.lua',
  'view/view.lua',
  'workarounds/workarounds.lua',
]


subdir('bogus_log')
# cookies module is not currently used
subdir('daf')
subdir('dnstap')
subdir('edns_keepalive')
subdir('hints')
subdir('http')
subdir('nsid')
subdir('policy')
subdir('stats')


# install lua modules
foreach mod : lua_src
  install_data(
    mod,
    install_dir: modules_dir,
  )
endforeach

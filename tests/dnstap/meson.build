
# note: it will be skipped if 'go' is missing (and marked so)
test('dnstap',
  find_program('./src/dnstap-test/run.sh'),
  args: [ sbin_dir / 'kresd' ],
  suite: [ 'postinstall', 'dnstap' ],
  timeout: 120, # it may need to fetch go packages, etc.
  # it takes relatively long time
  kwargs: meson.version().version_compare('<0.52') ? {} : { 'priority': 5 },
)


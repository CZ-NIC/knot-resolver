py3.install_sources(
    files(
        '__init__.py',
        'cache_schema.py',
        'config_schema.py',
        'dns64_schema.py',
        'dnssec_schema.py',
        'forward_zone_schema.py',
        'logging_schema.py',
        'lua_schema.py',
        'monitoring_schema.py',
        'network_schema.py',
        'options_schema.py',
        'policy_schema.py',
        'rpz_schema.py',
        'slice_schema.py',
        'static_hints_schema.py',
        'stub_zone_schema.py',
        'view_schema.py',
        'webmgmt_schema.py',
    ),
    subdir: manager_module_dir / datamodel_dir
)

templates_dir = 'templates'
subdir(templates_dir)

types_dir = 'types'
subdir(types_dir)
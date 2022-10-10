py3.extension_module(
    'notify',
    'notifymodule.c',
    subdir: manager_module_dir / kresd_controller_dir / supervisord_dir / plugin_dir
)

py3.install_sources(
    files(
        '__init__.py',
        'fast_rpcinterface.py',
        'manager_lifecycle_monitor.py',
        'stdout_pipe_log.py',
    ),
    subdir: manager_module_dir / kresd_controller_dir / supervisord_dir / plugin_dir
)
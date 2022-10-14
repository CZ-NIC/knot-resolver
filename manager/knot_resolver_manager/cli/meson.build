if get_option('manager_client') != 'disabled'
    build_manager_client = true
endif

if build_manager_client

    cmd_dir = 'cmd'
    subdir(cmd_dir)

    py3.install_sources(
        files(
            '__init__.py',
            '__main__.py',
        ),
        subdir: manager_module_dir / cli_dir
    )

    configure_file(
        input: 'cli.in',
        output: 'kresctl',
        install_mode: ['rwxr-xr-x', user, group],
        configuration: configuration_data({
            'cmd': ' '.join([py3.path(), '-m', manager_module_dir+'.'+cli_dir, '$@'])
        }),
        install_dir: get_option('sbindir'),
    )

endif
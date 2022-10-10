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

    # install_data(
    #     sources : 'kresctl',
    #     install_dir: get_option('sbindir'),
    # )

endif
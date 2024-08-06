# pylint: skip-file
# flake8: noqa


def run():
    # throws nice syntax error on old Python versions:
    0_0  # Python >= 3.7 required

    from knot_resolver_manager.manager import main

    main.main()


if __name__ == "__main__":
    run()

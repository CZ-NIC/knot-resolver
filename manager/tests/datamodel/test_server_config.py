from knot_resolver_manager.datamodel.server_config import Server, ServerStrict

yaml = """
hostname: myhostname
groupid: group1
nsid: mynsid
workers: 4
use-cache-gc: false
management:
    listen: /tmp/manager.sock
    backend: systemd
    rundir: "."
"""

config = Server.from_yaml(yaml)
strict = ServerStrict(config)


def test_parsing():
    assert config.hostname == "myhostname"
    assert config.groupid == "group1"
    assert config.nsid == "mynsid"
    assert config.workers == 4
    assert config.use_cache_gc == False
    assert config.management.listen == "/tmp/manager.sock"
    assert config.management.backend == "systemd"
    assert config.management.rundir == "."


def test_validating():
    assert strict.hostname == "myhostname"
    assert strict.groupid == "group1"
    assert strict.nsid == "mynsid"
    assert strict.workers == 4
    assert strict.use_cache_gc == False
    assert strict.management.listen == "/tmp/manager.sock"
    assert strict.management.backend == "systemd"
    assert strict.management.rundir == "."

from knot_resolver.controller.subprocess import SubprocessID, SubprocessType


def test_subprocess_id() -> None:
    worker0 = SubprocessID.alloc(SubprocessType.WORKER)
    worker1 = SubprocessID.alloc(SubprocessType.WORKER)
    worker2 = SubprocessID.alloc(SubprocessType.WORKER)

    loader = SubprocessID.alloc(SubprocessType.LOADER)
    cache_gc = SubprocessID.alloc(SubprocessType.CACHE_GC)

    assert worker0 is not worker1 is not worker2 is not loader is not cache_gc

    assert worker0 is SubprocessID(SubprocessType.WORKER, 0)
    assert worker1 is SubprocessID(SubprocessType.WORKER, 1)
    assert worker2 is SubprocessID(SubprocessType.WORKER, 2)

    assert loader.subprocess_num == 0
    assert cache_gc.subprocess_num == 0

import pytest

from knot_resolver.controller.subprocess import (
    SubprocessID,
    SubprocessStatus,
    SubprocessType,
)


@pytest.fixture(autouse=True)
def reset_subprocess_ids():
    """Keep the class-level ID registry isolated between tests."""
    SubprocessID._used.clear()
    yield
    SubprocessID._used.clear()


class TestSubprocessType:
    def test_values(self):
        assert SubprocessType.MANAGER.value == "manager"
        assert SubprocessType.WORKER.value == "worker"
        assert SubprocessType.LOADER.value == "loader"
        assert SubprocessType.CACHE_GC.value == "cache-gc"

    def test_is_str_enum(self):
        assert isinstance(SubprocessType.WORKER, str)
        assert str(SubprocessType.WORKER) == "SubprocessType.WORKER"


class TestSubprocessStatus:
    def test_values(self):
        assert SubprocessStatus.STOPPED == 0
        assert SubprocessStatus.STARTING == 10
        assert SubprocessStatus.RUNNING == 20
        assert SubprocessStatus.BACKOFF == 30
        assert SubprocessStatus.STOPPING == 40
        assert SubprocessStatus.EXITED == 100
        assert SubprocessStatus.FATAL == 200
        assert SubprocessStatus.UNKNOWN == 1000

    def test_is_ordered(self):
        assert SubprocessStatus.STOPPED < SubprocessStatus.STARTING
        assert SubprocessStatus.STARTING < SubprocessStatus.RUNNING
        assert SubprocessStatus.RUNNING < SubprocessStatus.BACKOFF
        assert SubprocessStatus.BACKOFF < SubprocessStatus.STOPPING
        assert SubprocessStatus.STOPPING < SubprocessStatus.EXITED
        assert SubprocessStatus.EXITED < SubprocessStatus.FATAL
        assert SubprocessStatus.FATAL < SubprocessStatus.UNKNOWN


class TestSubprocessID:
    def test_creates_id(self):
        subprocess_id = SubprocessID(SubprocessType.WORKER, 1)

        assert subprocess_id.subprocess_type is SubprocessType.WORKER
        assert subprocess_id.subprocess_num == 1

    @pytest.mark.parametrize(
        ("subprocess_type", "subprocess_num", "expected_name"),
        [
            (SubprocessType.MANAGER, 0, "manager"),
            (SubprocessType.WORKER, 0, "worker:worker0"),
            (SubprocessType.WORKER, 1, "worker:worker1"),
            (SubprocessType.LOADER, 0, "loader"),
            (SubprocessType.CACHE_GC, 0, "cache-gc"),
        ],
    )
    def test_subprocess_name(
        self,
        subprocess_type,
        subprocess_num,
        expected_name,
    ):
        subprocess_id = SubprocessID(subprocess_type, subprocess_num)

        assert subprocess_id.subprocess_name == expected_name

    def test_same_type_and_number_returns_same_instance(self):
        first = SubprocessID(SubprocessType.WORKER, 1)
        second = SubprocessID(SubprocessType.WORKER, 1)

        assert first is second

    def test_different_numbers_return_different_instances(self):
        first = SubprocessID(SubprocessType.WORKER, 0)
        second = SubprocessID(SubprocessType.WORKER, 1)

        assert first is not second

    def test_different_types_return_different_instances(self):
        worker = SubprocessID(SubprocessType.WORKER, 0)
        loader = SubprocessID(SubprocessType.LOADER, 0)

        assert worker is not loader

    def test_alloc_starts_at_zero(self):
        subprocess_id = SubprocessID.alloc(SubprocessType.WORKER)

        assert subprocess_id.subprocess_num == 0
        assert subprocess_id.subprocess_type is SubprocessType.WORKER

    def test_alloc_returns_next_free_number(self):
        SubprocessID(SubprocessType.WORKER, 0)
        SubprocessID(SubprocessType.WORKER, 1)

        subprocess_id = SubprocessID.alloc(SubprocessType.WORKER)

        assert subprocess_id.subprocess_num == 2

    def test_alloc_reuses_gap(self):
        SubprocessID(SubprocessType.WORKER, 0)
        SubprocessID(SubprocessType.WORKER, 2)

        subprocess_id = SubprocessID.alloc(SubprocessType.WORKER)

        assert subprocess_id.subprocess_num == 1

    def test_alloc_is_independent_per_type(self):
        worker = SubprocessID.alloc(SubprocessType.WORKER)
        loader = SubprocessID.alloc(SubprocessType.LOADER)

        assert worker.subprocess_num == 0
        assert loader.subprocess_num == 0
        assert worker is not loader

    def test_returns_existing_instance(self):
        allocated = SubprocessID.alloc(SubprocessType.WORKER)

        existing = SubprocessID(SubprocessType.WORKER, 0)

        assert allocated is existing

    def test_repr(self):
        subprocess_id = SubprocessID(SubprocessType.WORKER, 3)

        assert repr(subprocess_id) == "SubprocessID(worker, 3)"

    def test_equal_ids_are_equal(self):
        first = SubprocessID(SubprocessType.WORKER, 1)
        second = SubprocessID(SubprocessType.WORKER, 1)

        assert first == second

    def test_different_numbers_are_not_equal(self):
        first = SubprocessID(SubprocessType.WORKER, 1)
        second = SubprocessID(SubprocessType.WORKER, 2)

        assert first != second

    def test_different_types_are_not_equal(self):
        worker = SubprocessID(SubprocessType.WORKER, 0)
        loader = SubprocessID(SubprocessType.LOADER, 0)

        assert worker != loader

    @pytest.mark.parametrize(
        "other",
        [
            None,
            1,
            "worker:worker0",
            ("worker", 0),
            object(),
        ],
    )
    def test_not_equal_to_other_types(self, other):
        subprocess_id = SubprocessID(SubprocessType.WORKER, 0)

        assert subprocess_id != other

    def test_hash_is_based_on_type_and_number(self):
        subprocess_id = SubprocessID(SubprocessType.WORKER, 1)

        assert hash(subprocess_id) == hash((SubprocessType.WORKER, 1))

    def test_equal_ids_have_equal_hashes(self):
        first = SubprocessID(SubprocessType.WORKER, 1)
        second = SubprocessID(SubprocessType.WORKER, 1)

        assert hash(first) == hash(second)

    def test_can_be_used_as_dict_key(self):
        subprocess_id = SubprocessID(SubprocessType.WORKER, 1)
        mapping = {subprocess_id: "running"}

        equivalent_id = SubprocessID(SubprocessType.WORKER, 1)

        assert mapping[equivalent_id] == "running"

    def test_can_be_used_in_set(self):
        first = SubprocessID(SubprocessType.WORKER, 1)
        second = SubprocessID(SubprocessType.WORKER, 1)

        assert {first, second} == {first}

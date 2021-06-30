import logging
from sys import exc_info
from typing import Callable

from knot_resolver_manager.client import KnotManagerClient, count_running_kresds, start_manager_in_background

PORT = 5001
HOST = "localhost"
BASE_URL = f"http://{HOST}:{PORT}"


Test = Callable[[KnotManagerClient], None]


logger = logging.getLogger(__name__)


def test_wrapper(test: Test):
    p = start_manager_in_background(HOST, PORT)
    client = KnotManagerClient(BASE_URL)
    client.wait_for_initialization()

    logger.info("Starting test %s", test.__name__)
    try:
        res = test(client)
    except AssertionError:
        logger.error("Test %s failed", exc_info=True)
        res = False

    try:
        client.stop()
        p.join()
    except Exception:
        logger.warn("Failed to stop manager gracefully, terminating by force...")
        p.terminate()
        p.join()

    return res


def worker_count(client: KnotManagerClient):
    client.set_num_workers(2)
    cnt = count_running_kresds()
    assert cnt == 2, f"Expected 2 kresd instances, found {cnt}"

    client.set_num_workers(1)
    cnt = count_running_kresds()
    assert cnt == 1, f"Expected 1 kresd instance, found {cnt}"


def crash_resistance(client: KnotManagerClient):
    client.set_num_workers(2)
    cnt = count_running_kresds()
    assert cnt == 2, f"Expected 2 kresd instances, found {cnt}"

    # kill the server
    # p.terminate()
    # p.join()

    # no change in number of workers should be visible
    cnt = count_running_kresds()
    assert cnt == 2, f"Expected 2 kresd instances, found {cnt}"

    # start the server again
    p = start_manager_in_background("localhost", PORT, initial_config=None)
    client.wait_for_initialization()

    # no change in number of workers should be visible
    cnt = count_running_kresds()
    assert cnt == 2, f"Expected 2 kresd instances, found {cnt}"

    # however the manager should now react to changes
    client.set_num_workers(1)
    cnt = count_running_kresds()
    assert cnt == 1, f"Expected 1 kresd instance, found {cnt}"


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    test_wrapper(worker_count)
    # test_wrapper(crash_resistance)

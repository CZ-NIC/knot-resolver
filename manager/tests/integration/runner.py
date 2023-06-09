import logging
import sys
from pathlib import Path
from typing import Callable

from knot_resolver_manager.client import KnotManagerClient, count_running_kresds, start_manager_in_background

PORT = 5001
HOST = "localhost"
BASE_URL = f"http://{HOST}:{PORT}"


Test = Callable[[KnotManagerClient], None]


logger = logging.getLogger(__name__)


def test_wrapper(test: Test) -> bool:
    p = start_manager_in_background(Path("tests/integration/config.yml"))
    client = KnotManagerClient(BASE_URL)
    client.wait_for_initialization()

    logger.info("Starting test %s", test.__name__)
    try:
        test(client)
        res = True
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
    p = start_manager_in_background(Path("test/integration/config.yml"))
    try:
        client.wait_for_initialization()
    except TimeoutError as e:
        p.terminate()
        raise e

    # no change in number of workers should be visible
    cnt = count_running_kresds()
    assert cnt == 2, f"Expected 2 kresd instances, found {cnt}"

    # however the manager should now react to changes
    client.set_num_workers(1)
    cnt = count_running_kresds()
    assert cnt == 1, f"Expected 1 kresd instance, found {cnt}"


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    # create run directories if it does not exist
    Path("tests/integration/run").mkdir(exist_ok=True)

    # run the tests
    success = True
    success &= test_wrapper(worker_count)
    # success &= test_wrapper(crash_resistance)

    # exit with proper exitcode
    sys.exit(int(not success))

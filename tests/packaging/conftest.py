# SPDX-License-Identifier: GPL-3.0-or-later

import pytest
import os


def pytest_configure():
    pytest.KR_PYTESTS_DIR = os.path.dirname(os.path.realpath(__file__))
    pytest.KR_ROOT_DIR = os.path.join(pytest.KR_PYTESTS_DIR, "..", "..")
    pytest.KR_PREFIX = "kr-packaging-tests-"

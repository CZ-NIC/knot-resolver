Transport tests
===============

Requirements
------------

- pip3 install -r requirements.txt

Executing tests
---------------

```
pytest-3  # sequential, all tests
pytest-3 test_conn_mgmt.py::test_ignore_garbage   # specific test only
pytest-3 -n 8  # parallel with 8 jobs - requires pytest-xdist
```

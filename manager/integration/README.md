# Integration test tool

## Rationale behind this tool

We want to test the Knot Resolver manager in environments similar to the one where it will be running in production. The tests should be reproducible. At the time of writing this, we are dependent on systemd and having root privileges.

The solution is rather simple - every test case is a full-blown system in a rootless Podman container. The containers are managed automatically and after the initial setup, the tests should just run.

## Setup

Install Podman and configure it so that it can run in a rootless mode. The tool was developed against Podman 3.0.1, however it should probably work with versions as old as 2.0.0 (that's when the HTTP API was introduced).

## What is a test?

A single test is a directory in `tests`. It has to contain `Dockerfile`. The container created by the `Dockerfile` has to have an executable called `/test` in its file system. The `Dockerfile` must be configured to execute systemd on container startup. The `/test` executable is then called manually by the testing tool.

Exit code of the `/test` script determines the result of a test. 0 means test successfull, non-zero unsuccessful.

## How does the integration tool work?

The tool launches a Podman subprocess which exposes a HTTP API. This API is then used to control the containers.

For each directory in `tests/`, the testing tool builds the container, starts it, exec's `/test` and observes its result. After that, it issues `systemctl poweroff` and waits until the container turns itself off.

Because building the container is slow (even with Podman's caching), we skip it if it's not needed. The testing tool creates a `.contentshash` file within each test directory, which contains a hash of all content. The container is rebuilt only when the hash changes (or the file is missing).



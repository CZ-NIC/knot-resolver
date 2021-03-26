#!/usr/bin/env python

import subprocess
import sys
import time
from pathlib import Path, PurePath
from typing import Dict, List, Optional

import click

PODMAN_EXECUTABLE = "/usr/bin/podman"


def start_detached(
    image: str, publish: List[int] = [], ro_mounts: Dict[PurePath, PurePath] = {}
) -> str:
    """Start a detached container"""
    options = [f"--publish={port}:{port}/tcp" for port in publish] + [
        f"--mount=type=bind,source={str(src)},destination={str(dst)},ro=true"
        for src, dst in ro_mounts.items()
    ]
    command = ["podman", "run", "--rm", "-d", *options, image]
    proc = subprocess.run(
        command, shell=False, executable=PODMAN_EXECUTABLE, stdout=subprocess.PIPE
    )
    assert proc.returncode == 0
    return str(proc.stdout, "utf8").strip()


def exec(container_id: str, cmd: List[str]) -> int:
    command = ["podman", "exec", container_id] + cmd
    return subprocess.call(command, shell=False, executable=PODMAN_EXECUTABLE)


def exec_interactive(container_id: str, cmd: List[str]) -> int:
    command = ["podman", "exec", "-ti", container_id] + cmd
    return subprocess.call(command, shell=False, executable=PODMAN_EXECUTABLE)


def stop(container_id: str):
    command = ["podman", "stop", container_id]
    ret = subprocess.call(command, shell=False, executable=PODMAN_EXECUTABLE)
    assert ret == 0


def _get_git_root() -> PurePath:
    result = subprocess.run(
        "git rev-parse --show-toplevel", shell=True, stdout=subprocess.PIPE
    )
    return PurePath(str(result.stdout, encoding="utf8").strip())


@click.command()
@click.argument("image", nargs=1)
@click.argument("command", nargs=-1)
@click.option(
    "-p", "--publish", "publish", multiple=True, type=int, help="Port which should be published"
)
@click.option(
    "-m",
    "--mount",
    "mount",
    multiple=True,
    nargs=1,
    type=str,
    help="Read-only bind mounts into the container, value /path/on/host:/path/in/container",
)
@click.option(
    "-c",
    "--code",
    "mount_code",
    default=False,
    is_flag=True,
    type=bool,
    help="Shortcut to mount gitroot into /code",
)
def main(
    image: str,
    command: List[str],
    publish: Optional[int],
    mount: Optional[List[str]],
    mount_code: bool,
):
    # make sure arguments have the correct type
    image = str(image)
    command = list(command)
    publish = [] if publish is None else [int(p) for p in publish]
    mount = [] if mount is None else [x.split(":") for x in mount]
    mount_path = {Path(x[0]).absolute(): Path(x[1]).absolute() for x in mount}
    for src_path in mount_path:
        if not src_path.exists():
            print(
                f'The specified path "{str(src_path)}" does not exist on the host system',
                file=sys.stderr,
            )
            exit(1)
    if mount_code:
        mount_path[_get_git_root()] = Path("/code")

    cont = start_detached(image, publish=publish, ro_mounts=mount_path)
    # wait for the container to boot properly
    time.sleep(0.5)
    # run the command
    ret = exec_interactive(cont, command)
    # stop the container
    stop(cont)


if __name__ == "__main__":
    main()

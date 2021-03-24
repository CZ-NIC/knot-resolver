#!/usr/bin/env python

import subprocess
from typing import List, Optional
import click
import time
import itertools

PODMAN_EXECUTABLE = "/usr/bin/podman"

def start_detached(image: str, publish: List[int] = []) -> str:
    """Start a detached container"""
    options = [ f"--publish={port}:{port}/tcp" for port in publish ]
    command = ["podman", "run", "--rm", "-d", *options, image]
    proc = subprocess.run(command, shell=False, executable=PODMAN_EXECUTABLE, stdout=subprocess.PIPE)
    assert proc.returncode == 0
    return str(proc.stdout, 'utf8').strip()

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


@click.command()
@click.argument("image", nargs=1)
@click.argument("command", nargs=-1)
@click.option("-p", "--publish", "publish", type=int, help="Port which should we publish")
def main(image: str, command: List[str], publish: Optional[int]):
    # make sure arguments have the correct type
    image = str(image)
    command = list(command)
    publish = [] if publish is None else [int(publish)]

    cont = start_detached(image, publish=publish)
    # wait for the container to boot properly
    time.sleep(0.5)
    # run the command
    ret = exec_interactive(cont, command)
    # stop the container
    stop(cont)

if __name__ == "__main__":
    main()
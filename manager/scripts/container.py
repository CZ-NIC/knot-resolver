#!/usr/bin/env python

import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, NoReturn, Optional
from os import environ
import atexit

import click

def _get_git_root() -> Path:
    result = subprocess.run(
        "git rev-parse --show-toplevel", shell=True, stdout=subprocess.PIPE
    )
    return Path(str(result.stdout, encoding="utf8").strip())


GIT_ROOT: Path = _get_git_root()
PODMAN_EXECUTABLE = "/usr/bin/podman"
CACHE_DIR: Path = GIT_ROOT / ".podman-cache"




def _start_detached(
    image: str, publish: List[int] = [], ro_mounts: Dict[Path, Path] = {}
) -> str:
    """Start a detached container"""
    options = [f"--publish={port}:{port}/tcp" for port in publish] + [
        f"--volume={str(src)}:{str(dst)}:O"
        for src, dst in ro_mounts.items()
    ]
    command = ["podman", "run", "--rm", "-d", *options, image]
    proc = subprocess.run(
        command, shell=False, executable=PODMAN_EXECUTABLE, stdout=subprocess.PIPE
    )
    assert proc.returncode == 0
    return str(proc.stdout, "utf8").strip()


def _exec(container_id: str, cmd: List[str]) -> int:
    command = ["podman", "exec", container_id] + cmd
    return subprocess.call(command, shell=False, executable=PODMAN_EXECUTABLE)


def _exec_interactive(container_id: str, cmd: List[str]) -> int:
    command = ["podman", "exec", "-ti", container_id] + cmd
    return subprocess.call(command, shell=False, executable=PODMAN_EXECUTABLE)


def _stop(container_id: str):
    command = ["podman", "stop", container_id]
    ret = subprocess.call(command, shell=False, executable=PODMAN_EXECUTABLE)
    assert ret == 0


def _list_available_image_tags() -> List[str]:
    res: List[str] = []
    for c in (GIT_ROOT / "containers").iterdir():
        if c.is_dir():
            res.append(c.name)
    res.sort()  # make the order reproducible
    return res


def _extract_tag_from_name(name: str, all: List[str] = _list_available_image_tags()) -> str:
    if ":" in name:
        s = name.split(":")
        if not s[0].endswith("knot-manager"):
            click.secho(f"Unexpected image name \'{s[0]}\', expected \'knot-manager\'", fg="red")
            sys.exit(1)
        name = s[-1]
    
    if not name in all:
        click.secho(f"Unexpected tag \'{name}\'", fg="red")
        click.secho(f"Available tags are [{' '.join(all)}]", fg="yellow")
        sys.exit(1)
    
    return name

def _get_tags_to_work_on(args: List[str]) -> List[str]:
    args = list(args)

    all = _list_available_image_tags()

    # convert to tags, if the user specified full names
    for i,a in enumerate(args):
        args[i] = _extract_tag_from_name(a, all)

    if len(args) == 0:
        args = all

    return args


def _full_name_from_tag(tag: str) -> str:
    return f"registry.nic.cz/knot/knot-resolver-manager/knot-manager:{tag}"


def _build(tag: str):
    command = ["podman", "build", "-f", str(GIT_ROOT / "containers" / tag / "Containerfile"), "-t", _full_name_from_tag(tag), str(GIT_ROOT)]
    ret = subprocess.call(command, shell=False, executable=PODMAN_EXECUTABLE)
    assert ret == 0


def _pull(tag: str):
    command = ["podman", "pull", _full_name_from_tag(tag)]
    ret = subprocess.call(command, shell=False, executable=PODMAN_EXECUTABLE)
    assert ret == 0


def _push(tag: str):
    command = ["podman", "push", _full_name_from_tag(tag)]
    ret = subprocess.call(command, shell=False, executable=PODMAN_EXECUTABLE)
    assert ret == 0


def _login_ci():
    command = ["podman", "login", "-u", environ["CI_REGISTRY_USER"], "-p", environ["CI_REGISTRY_PASSWORD"], environ["CI_REGISTRY"]]
    ret = subprocess.call(command, shell=False, executable=PODMAN_EXECUTABLE)
    assert ret == 0


def _save(tag: str):
    CACHE_DIR.mkdir(exist_ok=True)
    command = ["podman", "save", "--format", "oci-archive", "-o", str(CACHE_DIR / (tag + ".tar")), _full_name_from_tag(tag)]
    ret = subprocess.call(command, shell=False, executable=PODMAN_EXECUTABLE)
    assert ret == 0

def _load(tag: str):
    cache_file = CACHE_DIR / (tag + ".tar")
    if cache_file.exists():
        command = ["podman", "load", "-i", str(CACHE_DIR / (tag + ".tar"))]
        ret = subprocess.call(command, shell=False, executable=PODMAN_EXECUTABLE)
        assert ret == 0



@click.group()
def main():
    pass


@main.command(help="Pull CI built images")
@click.argument("images", nargs=-1)
def pull(images: List[str]):
    tags = _get_tags_to_work_on(images)

    for tag in tags:
        click.secho(f"Pulling image with tag {tag}", fg="yellow")
        _pull(tag)



@main.command(help="Build project containers")
@click.argument("images", nargs=-1)
@click.option("-f", "--fetch", "fetch", is_flag=True, default=False, type=bool, help="Pull before building")
@click.option("--ci-login", "ci_login", is_flag=True, default=False, type=bool, help="Login to registry in CI")
@click.option("-p", "--push", "push", is_flag=True, default=False, type=bool, help="Push images after building")
@click.option("--file-cache", is_flag=True, default=False, help="Try to utilise file cache")
def build(images: List[str], fetch: bool, ci_login: bool, push: bool, file_cache: bool):
    tags = _get_tags_to_work_on(images)

    if ci_login:
        _login_ci()
    
    for tag in tags:
        if fetch:
            click.secho(f"Pulling image with tag {tag}", fg="yellow")
            _pull(tag)
        
        if file_cache:
            _load(tag)

        click.secho(f"Building image with tag {tag}", fg="yellow")
        _build(tag)

        if push:
            click.secho(f"Pushing image with {tag}", fg="yellow")
            _push(tag)
        
        if file_cache:
            _save(tag)


@main.command(help="Run project containers")
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
@click.option(
    "-i",
    "--interactive",
    "interactive_inspection",
    default=False,
    is_flag=True,
    type=bool,
    help="Drop into interactive shell if the command fails"
)
def run(
    image: str,
    command: List[str],
    publish: Optional[List[int]],
    mount: Optional[List[str]],
    mount_code: bool,
    interactive_inspection: bool,
) -> NoReturn:
    # make sure arguments have the correct type
    tag = _extract_tag_from_name(image)
    command = list(command)
    publishI = [] if publish is None else [int(p) for p in publish]
    mountI = [] if mount is None else [x.split(":") for x in mount]
    mount_path = {Path(x[0]).absolute(): Path(x[1]).absolute() for x in mountI}
    for src_path in mount_path:
        if not src_path.exists():
            print(
                f'The specified path "{str(src_path)}" does not exist on the host system',
                file=sys.stderr,
            )
            exit(1)
    if mount_code:
        mount_path[GIT_ROOT] = Path("/code")

    cont = _start_detached(_full_name_from_tag(tag), publish=publishI, ro_mounts=mount_path)

    # register cleanup function
    def cleanup():
        _stop(cont)
    atexit.register(cleanup)

    # wait for the container to boot properly
    time.sleep(0.5)
    # run the command
    exit_code = _exec_interactive(cont, command)

    if interactive_inspection and exit_code != 0:
        print(f"The command {command} failed with exit code {exit_code}.")
        print("Dropping into an interactive shell as requested. Stop the shell to stop the whole container.")
        print("-----------------------------")
        _exec_interactive(cont, ["/bin/bash"])

    # the container should be stopped by the `atexit` module
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
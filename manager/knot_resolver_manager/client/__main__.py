import ipaddress
import sys

import click
from click.exceptions import ClickException

from knot_resolver_manager.client import KnotManagerClient
from knot_resolver_manager.datamodel.config_schema import KresConfig
from knot_resolver_manager.exceptions import KresManagerException
from knot_resolver_manager.utils.parsing import parse_yaml

BASE_URL = "base_url"


@click.group()
@click.option(
    "-u",
    "--url",
    "base_url",
    nargs=1,
    default="http://localhost:5000/",
    help="Set base URL on which the manager communicates",
)
@click.pass_context
def main(ctx: click.Context, base_url: str) -> None:
    ctx.ensure_object(dict)
    ctx.obj[BASE_URL] = base_url


@main.command(help="Shutdown the manager and all workers")
@click.pass_context
def stop(ctx: click.Context) -> None:
    client = KnotManagerClient(ctx.obj[BASE_URL])
    client.stop()


@main.command("gen-lua", help="Generate LUA config from a given declarative config")
@click.argument("config_path", type=str, nargs=1)
def gen_lua(config_path: str) -> None:
    try:
        with open(config_path, "r", encoding="utf8") as f:
            data = f.read()
        parsed = parse_yaml(data)
        config = KresConfig(parsed)
        lua = config.render_lua()
        click.echo_via_pager(lua)
    except KresManagerException as e:
        ne = ClickException(str(e))
        ne.exit_code = 1
        raise ne


@main.command(help="Set number of workers")
@click.argument("instances", type=int, nargs=1)
@click.pass_context
def workers(ctx: click.Context, instances: int) -> None:
    client = KnotManagerClient(ctx.obj[BASE_URL])
    client.set_num_workers(instances)


@main.command(help="Set the manager groupid")
@click.argument("gid", type=str, nargs=1)
@click.pass_context
def groupid(ctx: click.Context, gid: str) -> None:
    client = KnotManagerClient(ctx.obj[BASE_URL])
    client.set_groupid(gid)


@main.command("one-static-hint", help="Set one inline static-hint hints (replaces old static hints)")
@click.argument("name", type=str, nargs=1)
@click.argument("ip", type=str, nargs=1)
@click.pass_context
def one_static_hint(ctx: click.Context, name: str, ip: str) -> None:
    client = KnotManagerClient(ctx.obj[BASE_URL])
    client.set_static_hints({name: [ipaddress.ip_address(ip)]})


@main.command("listen-ip", help="Configure where the resolver should listen (replaces all previous locations)")
@click.argument("ip", type=str, nargs=1)
@click.argument("port", type=int, nargs=1)
@click.pass_context
def listen_ip(ctx: click.Context, ip: str, port: int) -> None:
    client = KnotManagerClient(ctx.obj[BASE_URL])
    client.set_listen_ip_address(ipaddress.ip_address(ip), port)


@main.command(help="Wait for manager initialization")
@click.pass_context
def wait(ctx: click.Context) -> None:
    client = KnotManagerClient(ctx.obj[BASE_URL])
    try:
        client.wait_for_initialization()
    except TimeoutError as e:
        click.echo(f"ERR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter

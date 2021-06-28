import click

from knot_resolver_manager.client import KnotManagerClient

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
def main(ctx: click.Context, base_url: str):
    ctx.ensure_object(dict)
    ctx.obj[BASE_URL] = base_url


@main.command(help="Shutdown the manager and all workers")
@click.pass_context
def stop(ctx: click.Context):
    client = KnotManagerClient(ctx.obj[BASE_URL])
    client.stop()


@main.command(help="Set number of workers")
@click.argument("instances", type=int, nargs=1)
@click.pass_context
def workers(ctx: click.Context, instances: int):
    client = KnotManagerClient(ctx.obj[BASE_URL])
    client.set_num_workers(instances)


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter

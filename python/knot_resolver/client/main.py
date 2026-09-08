from pathlib import Path

from knot_resolver.datamodel.globals import Context, set_global_validation_context

from .args import parse_client_args

set_global_validation_context(Context(Path(), False))


def main() -> None:
    args = parse_client_args()

    command = args.command(args)
    command.run()

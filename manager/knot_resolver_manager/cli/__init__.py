from typing import TYPE_CHECKING, cast

from typing_extensions import Literal

from knot_resolver_manager.utils.requests import request

if TYPE_CHECKING:
    from knot_resolver_manager.cli.__main__ import Args, ConfigArgs


def config(args: "Args") -> None:
    cfg: "ConfigArgs" = cast("ConfigArgs", args.command)

    if not cfg.path.startswith("/"):
        cfg.path = "/" + cfg.path

    method: Literal["GET", "POST"] = "GET" if cfg.replacement_value is None else "POST"
    url = f"{args.socket}/v1/config{cfg.path}"
    response = request(method, url, cfg.replacement_value)
    print(response)


def stop(args: "Args") -> None:
    url = f"{args.socket}/stop"
    response = request("POST", url)
    print(response)

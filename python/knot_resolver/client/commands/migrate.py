import argparse
import copy
import sys
from typing import Any, Dict, List, Optional, Tuple, Type

from knot_resolver.client.command import Command, CommandArgs, CompWords, comp_get_words, register_command
from knot_resolver.constants import VERSION
from knot_resolver.utils.modeling.exceptions import DataParsingError
from knot_resolver.utils.modeling.parsing import DataFormat, try_to_parse


def _remove(config: Dict[str, Any], path: str) -> Optional[Any]:
    keys = path.split("/")
    last = keys[-1]

    current = config
    for key in keys[1:-1]:
        if key in current:
            current = current[key]
        else:
            return None
    if isinstance(current, dict) and last in current:
        val = copy.copy(current[last])
        del current[last]
        print(f"removed {path}")
        return val
    return None


def _add(config: Dict[str, Any], path: str, val: Any, rewrite: bool = False) -> None:
    keys = path.split("/")
    last = keys[-1]

    current = config
    for key in keys[1:-1]:
        if key not in current:
            current[key] = {}
        elif key in current and not isinstance(current[key], dict):
            current[key] = {}
        current = current[key]

    if rewrite or last not in current:
        current[last] = val
        print(f"added {path}")


def _rename(config: Dict[str, Any], path: str, new_path: str) -> None:
    val: Optional[Any] = _remove(config, path)
    if val:
        _add(config, new_path, val)


@register_command
class MigrateCommand(Command):
    def __init__(self, namespace: argparse.Namespace) -> None:
        super().__init__(namespace)
        self.input_file: str = namespace.input_file
        self.output_file: Optional[str] = namespace.output_file
        self.output_format: DataFormat = namespace.output_format

    @staticmethod
    def register_args_subparser(
        subparser: "argparse._SubParsersAction[argparse.ArgumentParser]",
    ) -> Tuple[argparse.ArgumentParser, "Type[Command]"]:
        migrate = subparser.add_parser("migrate", help="Migrates JSON or YAML configuration to the newer version.")

        migrate.set_defaults(output_format=DataFormat.YAML)
        output_formats = migrate.add_mutually_exclusive_group()
        output_formats.add_argument(
            "--json",
            help="Get migrated configuration data in JSON format.",
            const=DataFormat.JSON,
            action="store_const",
            dest="output_format",
        )
        output_formats.add_argument(
            "--yaml",
            help="Get migrated configuration data in YAML format, default.",
            const=DataFormat.YAML,
            action="store_const",
            dest="output_format",
        )

        migrate.add_argument(
            "input_file",
            type=str,
            help="File with configuration in YAML or JSON format.",
        )
        migrate.add_argument(
            "output_file",
            type=str,
            nargs="?",
            help="Optional, output file for migrated configuration in desired output format. If not specified, migrated configuration is printed.",
            default=None,
        )
        return migrate, MigrateCommand

    @staticmethod
    def completion(args: List[str], parser: argparse.ArgumentParser) -> CompWords:
        return comp_get_words(args, parser)

    def run(self, args: CommandArgs) -> None:  # noqa: PLR0912, PLR0915
        with open(self.input_file, "r") as f:
            data = f.read()

        try:
            parsed = try_to_parse(data)
        except DataParsingError as e:
            print(e, file=sys.stderr)
            sys.exit(1)

        new = parsed.copy()

        # REMOVE
        _remove(new, "/dnssec/refresh-time")
        _remove(new, "/dnssec/hold-down-time")
        _remove(new, "/dnssec/time-skew-detection")
        _remove(new, "/local-data/root-fallback-addresses")
        _remove(new, "/local-data/root-fallback-addresses-files")
        _remove(new, "/logging/debugging")
        _remove(new, "/max-workers")
        _remove(new, "/network/tls/auto-discovery")
        _remove(new, "/webmgmt")

        # RENAME/MOVE
        cache_key = "cache"
        if cache_key in new:
            gc_key = "garbage-collector"
            if gc_key in new[cache_key]:
                gc = new[cache_key][gc_key]
                if gc is False:
                    _add(new, "/cache/garbage-collector/enable", False)
                else:
                    _add(new, "/cache/garbage-collector/enable", True)
            prefetch_key = "prefetch"
            if prefetch_key in new[cache_key]:
                prediction_key = "prediction"
                if prediction_key in new[cache_key][prefetch_key]:
                    prediction = new[cache_key][prefetch_key][prediction_key]
                    if prediction is None:
                        _add(new, "/cache/prefetch/prediction/enable", False)
                    else:
                        _add(new, "/cache/prefetch/prediction/enable", True)
        _rename(new, "/defer/enabled", "/defer/enable")
        dns64_key = "dns64"
        if dns64_key in new:
            if new[dns64_key] is False:
                _add(new, "/dns64/enable", False, rewrite=True)
            else:
                _add(new, "/dns64/enable", True, rewrite=True)
        _rename(new, "/dns64/rev-ttl", "/dns64/reverse-ttl")
        dnssec_key = "dnssec"
        if dnssec_key in new:
            if new[dnssec_key] is False:
                _add(new, "/dnssec/enable", False, rewrite=True)
            else:
                # by default the DNSSEC is enabled
                pass
        _rename(new, "/dnssec/keep-removed", "/dnssec/trust-anchors-keep-removed")
        _rename(new, "/dnssec/trust-anchor-sentinel", "/dnssec/sentinel")
        _rename(new, "/dnssec/trust-anchor-signal-query", "/dnssec/signal-query")
        logging_key = "logging"
        if logging_key in new:
            dnstap_key = "dnstap"
            if dnstap_key in new[logging_key]:
                dnstap = new[logging_key][dnstap_key]
                if dnstap is None:
                    _add(new, "/logging/dnstap/enable", False)
                else:
                    _add(new, "/logging/dnstap/enable", True)

        _rename(new, "/logging/dnssec-bogus", "/dnssec/log-bogus")
        _rename(new, "/monitoring/enabled", "/monitoring/metrics")
        monitoring_key = "monitoring"
        if monitoring_key in new:
            graphite_key = "graphite"
            if graphite_key in new[monitoring_key]:
                graphite = new[monitoring_key][graphite_key]
                if graphite is False:
                    _add(new, "/monitoring/graphite/enable", False)
                else:
                    _add(new, "/monitoring/graphite/enable", True)
        network_key = "network"
        if network_key in new:
            proxy_protocol_key = "proxy-protocol"
            if proxy_protocol_key in new[network_key]:
                proxy_protocol = new[network_key][proxy_protocol_key]
                if proxy_protocol is None:
                    _add(new, "/network/proxy-protocol/enable", False)
                else:
                    _add(new, "/network/proxy-protocol/enable", True)
        _rename(new, "/network/tls/files-watchdog", "/network/tls/watchdog")
        rate_limiting_key = "rate-limiting"
        if rate_limiting_key in new:
            _add(new, "/rate-limiting/enable", True)

        # remove empty dicts
        new = {k: v for k, v in new.items() if v}

        dumped = self.output_format.dict_dump(new)
        if self.output_file:
            with open(self.output_file, "w") as f:
                f.write(dumped)
        else:
            print(f"\nNew migrated configuration (v{VERSION}):")
            print("---")
            print(dumped)

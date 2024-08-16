import argparse

from knot_resolver_manager.client.command import CommandArgs

KRES_CLIENT_NAME = "kresctl"


class KresClient:
    def __init__(
        self,
        namespace: argparse.Namespace,
        parser: argparse.ArgumentParser,
        prompt: str = KRES_CLIENT_NAME,
    ) -> None:
        self.path = None
        self.prompt = prompt
        self.namespace = namespace
        self.parser = parser

    def execute(self):
        if hasattr(self.namespace, "command"):
            args = CommandArgs(self.namespace, self.parser)
            command = args.command(self.namespace)
            command.run(args)
        else:
            self.parser.print_help()

    def _prompt_format(self) -> str:
        bolt = "\033[1m"
        white = "\033[38;5;255m"
        reset = "\033[0;0m"

        if self.path:
            prompt = f"{bolt}[{self.prompt} {white}{self.path}{reset}{bolt}]"
        else:
            prompt = f"{bolt}{self.prompt}"
        return f"{prompt}> {reset}"

    def interactive(self):
        try:
            while True:
                pass
                # TODO: not working yet
                # cmd = input(f"{self._prompt_format()}")
                # namespace = self.parser.parse_args(cmd.split(" "))
                # namespace.interactive = True
                # namespace.socket = self.namespace.socket
                # self.namespace = namespace
                # self.execute()
        except KeyboardInterrupt:
            pass

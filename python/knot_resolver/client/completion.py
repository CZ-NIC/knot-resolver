from __future__ import annotations

import argparse
from typing import TYPE_CHECKING, Optional, cast

if TYPE_CHECKING:
    from .command import KresClientCommand

COMP_DIRNAMES = "#dirnames#"
COMP_FILENAMES = "#filenames#"
COMP_NOSPACE = "#nospace#"

CompletionWords = dict[str, Optional[str]]


def get_mutually_exclusive_args(parser: argparse.ArgumentParser) -> list[set[str]]:
    groups: list[set[str]] = []

    for group in parser._mutually_exclusive_groups:
        group_args: set[str] = set()
        for action in group._group_actions:
            if action.option_strings:
                group_args.update(action.option_strings)
        if group_args:
            groups.append(group_args)
    return groups


def get_parser_action(name: str, parser_actions: list[argparse.Action]) -> argparse.Action | None:
    for action in parser_actions:
        if (action.choices and name in action.choices) or (action.option_strings and name in action.option_strings):
            return action
    return None


def get_subparser_command(subparser: argparse.ArgumentParser) -> type[KresClientCommand] | None:
    return cast(
        "type[KresClientCommand] | None",
        subparser._defaults.get("command"),
    )


def comp_get_actions_words(parser_actions: list[argparse.Action]) -> CompletionWords:
    words: CompletionWords = {}
    for action in parser_actions:
        if isinstance(action, argparse._SubParsersAction) and action.choices:
            for choice, parser in action.choices.items():
                words[choice] = parser.description if isinstance(parser, argparse.ArgumentParser) else None
        elif action.option_strings:
            for opt in action.option_strings:
                words[opt] = action.help
        elif not action.option_strings and action.choices:
            for choice in action.choices:
                words[choice] = action.help
        elif not action.option_strings and not action.choices:
            words[COMP_DIRNAMES] = None
            words[COMP_FILENAMES] = None
    return words


def comp_get_words(args: list[str], parser: argparse.ArgumentParser) -> CompletionWords:
    words: CompletionWords = comp_get_actions_words(parser._actions)
    nargs = len(args)

    skip_arg = False
    for i, arg in enumerate(args):
        action: argparse.Action | None = get_parser_action(arg, parser._actions)

        if skip_arg:
            skip_arg = False
            continue

        if not action:
            continue

        if i + 1 >= nargs:
            continue

        # remove exclusive arguments from words
        for exclusive_args in get_mutually_exclusive_args(parser):
            if arg in exclusive_args:
                for earg in exclusive_args:
                    if earg in words:
                        del words[earg]
        # remove alternative arguments from words
        for opt in action.option_strings:
            if opt in words:
                del words[opt]

        # if not action or action is HelpAction or VersionAction
        if isinstance(action, (argparse._HelpAction, argparse._VersionAction)):
            words = {}
            break

        # if action is StoreTrueAction or StoreFalseAction
        if isinstance(action, argparse._StoreConstAction):
            continue

        # if action is StoreAction
        if isinstance(action, argparse._StoreAction):
            if i + 2 >= nargs:
                choices = {}
                if action.choices:
                    for choice in action.choices:
                        choices[choice] = action.help
                else:
                    choices[COMP_DIRNAMES] = None
                    choices[COMP_FILENAMES] = None
                words = choices
            skip_arg = True
            continue

        # if action is SubParserAction
        if isinstance(action, argparse._SubParsersAction):
            subparser: argparse.ArgumentParser | None = action.choices.get(arg, None)

            command = get_subparser_command(subparser) if subparser else None
            if command and subparser:
                return command.completion(args[i + 1 :], subparser)
            if subparser:
                return comp_get_words(args[i + 1 :], subparser)
            return {}

    return words

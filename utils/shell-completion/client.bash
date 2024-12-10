#!/usr/bin/env bash

_kresctl_completion()
{
    COMPREPLY=()
    local cur prev opts words_up_to_cursor

    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    local line="${COMP_LINE:0:$COMP_POINT}"
    local words_up_to_cursor=($line)

    if [[ -z "$cur" && "$COMP_POINT" -gt 0 && "${line: -1}" == " " ]]
    then
        opts=$(kresctl completion --bash --space --args "${words_up_to_cursor[@]}")
    else
        opts=$(kresctl completion --bash --args "${words_up_to_cursor[@]}")
    fi

    # if we're completing a config path do not append a space
    # (unless we have reached the bottom)
    if [[ "$prev" == "-p" || "$prev" == "--path" ]] \
        && [[ $(echo "$opts" | wc -w) -gt 1 || "${opts: -1}" == '/' ]]
    then
        compopt -o nospace
    fi

    # if there is no completion from kresctl
    # auto-complete just directories and files
    if [[ -z "$opts" ]]
    then
        COMPREPLY=($(compgen -d -f -- "${cur}"))
    else
        COMPREPLY=($(compgen -W "${opts}" -- "${cur}"))
    fi

    return 0
}

complete -o filenames -o dirnames -F _kresctl_completion kresctl

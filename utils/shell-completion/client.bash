#/usr/bin/env bash

_kresctl_completion()
{
    COMPREPLY=()
    local cur prev opts

    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # check if there is a word is empty
    # that means there is a space after last non-empty word
    if [[ -z "$cur" ]]
    then
        # no word to complete, return all posible options
        opts=$(kresctl completion --bash --space "${COMP_WORDS}")
    else
        opts=$(kresctl completion --bash "${COMP_WORDS}")
    fi

    # if there is no completion from kresctl
    # auto-complete just directories and files
    if [[ -z "$opts" ]]
    then
        COMPREPLY=($(compgen -d -f "${cur}"))
    else
        COMPREPLY=( $(compgen -W "${opts}" ${cur}) )
    fi

    return 0
}

complete -o filenames -o dirnames -F _kresctl_completion kresctl

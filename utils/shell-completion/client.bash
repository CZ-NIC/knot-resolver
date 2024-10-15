#/usr/bin/env bash

_kresctl_completion()
{
    COMPREPLY=()
    local words=""
    local space_arg=""
    local cur="${COMP_WORDS[COMP_CWORD]}"

    # if the current word is empty
    # we need to inform the kresctl client about it
    if [[ -z "$cur" ]]; then
        space_arg="--space"
    fi

    # get words from the kresctl client
    words=$(kresctl completion --bash ${space_arg} --args "${COMP_WORDS[@]:1}")

    COMPREPLY=($(compgen  -W "${words}" -- "${cur}"))

    return 0
}

complete -o filenames -o dirnames -o nosort -F _kresctl_completion kresctl

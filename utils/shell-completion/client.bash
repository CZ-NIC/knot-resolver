#/usr/bin/env bash

_kresctl_completion()
{
    COMPREPLY=()
    local args=""
    local words=""
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local opts=$(kresctl completion --bash --args "${COMP_WORDS[@]:1}")

    # filter special opts
    for opt in $opts
    do
    if [[ "$opt" == "#dirnames#" ]]; then
        args="$args${args:+ }-d"
    elif [[ "$opt" == "#filenames#" ]]; then
        args="$args${args:+ }-f"
    elif [[ "$opt" == "#nospace#" ]]; then
        compopt -o nospace
    else
        words="$words${words:+ }$opt"
    fi
    done

    COMPREPLY=($(compgen $args -W "${words}" -- "${cur}"))
    return 0
}

complete -o nosort -F _kresctl_completion kresctl

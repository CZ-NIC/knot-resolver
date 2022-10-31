#/usr/bin/env bash

# completion function for the kresctl
__kresctl_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # get options
    opts=$(kresctl completion --bash "${COMP_WORDS}")

    if [[ ${cur} == -* || ${COMP_CWORD} -eq 1 ]] ; then
    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
    return 0
    fi

    return 0
}

# use the bash default completion for other arguments
complete -o filenames -o nospace -o bashdefault -F __kresctl_completion kresctl
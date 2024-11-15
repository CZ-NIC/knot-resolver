#/usr/bin/env bash

_kresctl_filter_double_dash()
{
    local words=("$@")
    local new_words=()
    local count=0

    for WORD in "${words[@]}"
    do
        if [[ "$WORD" != "--" ]]
        then
            new_words[count]="$WORD"
            ((count++))
        fi
    done

    printf "%s\n" "${new_words[@]}"
}

_kresctl_completion()
{
    COMPREPLY=()
    local cur opts cmp_words

    cur="${COMP_WORDS[COMP_CWORD]}"
    local line="${COMP_LINE:0:$COMP_POINT}"
    local words_up_to_cursor=($line)

    cmp_words=($(_kresctl_filter_double_dash "${words_up_to_cursor[@]}"))

    if [[ -z "$cur" && "$COMP_POINT" -gt 0 && "${line: -1}" == " " ]]
    then
        opts=$(kresctl completion --bash --space --args "${cmp_words[@]}")
    else
        opts=$(kresctl completion --bash --args "${cmp_words[@]}")
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

complete -o filenames -o dirnames -o nosort -F _kresctl_completion kresctl

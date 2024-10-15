#/usr/bin/env bash

_kresctl_skip_next=0

_kresctl_filter_switches()
{
    # skip kresctl, it is not a valid argument
    local words=("${COMP_WORDS[@]:1}")
    local new_words=()
    local count=0

    for WORD in "${words[@]}"
    do
        if [[ $_kresctl_skip_next -eq 0 ]]
        then
            if [[ ! $WORD =~ ^-{1,2} ]]
            then
                new_words[count]="$WORD"
                ((count++))
            else
                _kresctl_skip_next=1
            fi
        else
            _kresctl_skip_next=0
        fi

    done

    printf "%s\n" "${new_words[@]}"
    return $count
}


_kresctl_completion()
{
    COMPREPLY=()
    local cur opts cmp_words

    cur="${COMP_WORDS[COMP_CWORD]}"

    cmp_words=($(_kresctl_filter_switches))

    # check if there is a word is empty
    # that means there is a space after last non-empty word
    if [[ -z "$cur" ]]
    then
        # no word to complete, return all posible options
        opts=$(kresctl completion --bash --space "${cmp_words[@]}")
    else
        opts=$(kresctl completion --bash "${cmp_words[@]}")
    fi

    # if there is no completion from kresctl
    # auto-complete just directories and files
    if [[ -z "$opts" ]]
    then
        COMPREPLY=($(compgen -d -f -- "${cur}"))
    else
        COMPREPLY=($(compgen -W "${opts}" -- ${cur}))
    fi

    return 0
}

complete -o filenames -o dirnames -o nosort -F _kresctl_completion kresctl

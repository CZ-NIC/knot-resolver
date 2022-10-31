function __kresctl_completion
    set -l args (commandline -pco)
    eval command kresctl $args
end

complete -c kresctl -a '(__kresctl_completion)' -f
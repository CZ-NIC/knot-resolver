function __fish_git
    set -l args (commandline -pco)
    eval command kresctl $args
end

complete -c kresctl -a '(_kresctl_completion)' -f
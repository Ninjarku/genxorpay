#!/usr/bin/env bash

# Enable tab completion for ./genxorpay.sh
_genxorpay_completions()
{
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    opts="
        -p --payload
        -lhost
        -lport
        -rhost
        -key
        -o
        -raw
        -e --encoder
        --iterations
        --arch
        --platform
        --format
        --outdir
        --rotate
        -i --interactive
        --debug
        --nosuggest
        --example --ex -ex --xample ex EX xample
        -h --help
    "

    case "$prev" in
        -p|--payload)
            # Payload index completion
            COMPREPLY=( $(compgen -W "1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18" -- "$cur") )
            return 0
            ;;
        -e|--encoder)
            # Encoder index or name
            COMPREPLY=( $(compgen -W "1 2 3 4 5 6 7 8 9 10 11 x64/xor x86/shikata_ga_nai" -- "$cur") )
            return 0
            ;;
        --format)
            COMPREPLY=( $(compgen -W "exe vbapplication c elf" -- "$cur") )
            return 0
            ;;
        --arch)
            COMPREPLY=( $(compgen -W "x86 x64" -- "$cur") )
            return 0
            ;;
        --platform)
            COMPREPLY=( $(compgen -W "windows linux osx android php python java" -- "$cur") )
            return 0
            ;;
        *)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "${opts}" -- "$cur") )
                return 0
            fi
            ;;
    esac
}
complete -F _genxorpay_completions ./genxorpay.sh

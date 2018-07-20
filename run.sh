#!/bin/bash

pid="$1"
typ="$2"
if [ "$pid" == "" ] || [ "$typ" == "" ]; then
    echo "usage: $0 <pid> <type>"
    exit 1
fi

gcc -Wall -Wextra -pedantic -std=c11 phax.c -o ./phax

if [ $(cat /proc/sys/kernel/yama/ptrace_scope) -ne 0 ]; then
    sudo tee /proc/sys/kernel/yama/ptrace_scope <<< 0
fi

run() {
    ./phax "$pid" "$typ" $@
}

while :; do
    read -r -p 'phax> ' input
    case "$input" in
    search* )
        next_file=$(mktemp)
        run $input > $next_file && {
            cat $next_file
            prev_file=$next_file
        }
        ;;
    filter* )
        if [ "$prev_file" == "" ]; then
            echo "Must perform a search first!"
        else
            next_file=$(mktemp)
            run $input < $prev_file > $next_file && {
                cat $next_file
                prev_file=$next_file
            }
        fi
        ;;
    write* )
        if [ "$prev_file" == "" ]; then
            echo "Must perform a search first!"
        else
            run $input < $prev_file
        fi
        ;;
    exit )
        break
        ;;
    esac
done

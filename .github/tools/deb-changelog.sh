#!/bin/bash
#
# Converts ChangeLog.md (Keep a Changelog format) into Debian changelog
# entries.
#
# Usage:
#   deb-changelog.sh body <ChangeLog.md>
#     Prints the bullet items of the first (current/unreleased) section.
#   deb-changelog.sh date <ChangeLog.md>
#     Prints the RFC 2822 date for the first section (today if it has no
#     real date, e.g. "Unreleased").
#   deb-changelog.sh history <package-name> <ChangeLog.md>
#     Prints all remaining sections as full Debian changelog entries.

set -e

mode=$1

declare -a versions dates
declare -a items

section=-1
current_items=""

flush() {
    if [ $section -ge 0 ]; then
        items[$section]="$current_items"
    fi
}

read_sections() {
    local md=$1
    while IFS= read -r line || [ -n "$line" ]; do
        if [[ "$line" =~ ^##\ \[([^]]+)\]\ -\ (.*)$ ]]; then
            flush
            section=$((section + 1))
            versions[$section]="${BASH_REMATCH[1]}"
            dates[$section]="${BASH_REMATCH[2]}"
            current_items=""
        elif [ $section -ge 0 ] && [[ "$line" =~ ^-\ (.*)$ ]]; then
            current_items+="${BASH_REMATCH[1]}"$'\n'
        fi
    done < "$md"
    flush
}

to_rfc2822() {
    if [ "$1" = "Unreleased" ]; then
        date -R
    else
        date -R -d "$1" 2> /dev/null || date -R
    fi
}

print_body() {
    local idx=$1
    if [ -z "${items[$idx]}" ]; then
        echo "  * No notable changes yet."
    else
        while IFS= read -r item; do
            [ -n "$item" ] && echo "  * ${item}"
        done <<< "${items[$idx]}" || true
    fi
}

case "$mode" in
    body)
        read_sections "$2"
        print_body 0
        ;;
    date)
        read_sections "$2"
        to_rfc2822 "${dates[0]}"
        ;;
    history)
        pkg=$2
        read_sections "$3"
        for ((i = 1; i <= section; i++)); do
            echo "${pkg} (${versions[$i]}) unstable; urgency=medium"
            echo
            print_body "$i"
            echo
            echo " -- Vasily Stepanov <vasily.stepanov@gmail.com>  $(to_rfc2822 "${dates[$i]}")"
            if [ $i -lt $section ]; then
                echo
            fi
        done
        ;;
    *)
        echo "usage: $0 {body|date} <ChangeLog.md> | $0 history <package> <ChangeLog.md>" >&2
        exit 1
        ;;
esac

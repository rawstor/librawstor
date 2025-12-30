#!/bin/bash


function find_cmd() {
    IFS=','
    local paths="$1"
    local excludes="$2"
    local cmd=""

    cmd+="find . -type f "

    if [ -n "$excludes" ]; then
        for exclude in $excludes; do
            cmd+="! -path \"$exclude\" "
        done
    fi

    cmd+="\( "
    local is_first=1
    for path in $paths; do
        if [ $is_first -ne 1 ]; then
            cmd+="-o "
        fi
        cmd+="-path \"$path\" "
        is_first=0
    done
    cmd+=" \)"

    echo $cmd

    unset IFS
}


function check_file() {
    local file="$1"
    message="$(clang-format -n -Werror --ferror-limit=3 --style=file --fallback-style=LLVM "${file}")"
    local status="$?"
    if [ $status -ne 0 ]; then
        echo "$message" >&2
        return 1
    fi
    return 0
}


function main() {
    local input_pattern=$1
    local input_excludes=$2
    echo -e "Sources: $input_pattern"
    local cmd=$(find_cmd "$input_pattern" "$input_excludes")

    for file in $(eval $cmd); do
        echo -e "Checking file: $file"
        check_file "$file"
        if [ $? -ne 0 ]; then
            issues+=("$file")
        fi
    done

    if [ ${#issues[@]} -eq 0 ]; then
        echo -e "Success!!! The sources are clang formatted."
        exit 0
    else
        echo -e "Some file is not formatted correctly."
        echo -e "You might want to run: "
        for ((i = 0; i < ${#issues[@]}; i++)); do
            if [ $i -ne 0 ]; then
                echo " \\"
                echo -n " && "
            fi
            echo -n "clang-format --style=file -i "${issues[$i]}""
        done
        echo
        exit 1
    fi
}


main ${1:-"*.c,*.h,*.cpp,*.hpp"} ${2:-"**/**/3rdparty/*"}

#!/bin/bash

set -f


CLANG_FORMAT="clang-format-21"
if ! command -v ${CLANG_FORMAT} >/dev/null 2>&1
then
    echo "${CLANG_FORMAT} could not be found, falling back to clang-format"
    CLANG_FORMAT="clang-format"
fi


function find_cmd() {
    IFS=','
    local paths="$1"
    local cmd=""

    cmd+="find . -type f "

    cmd+="\( "
    local is_first=1
    for path in $paths; do
        # find .'s own output is always "./"-prefixed, so a plain relative
        # path (no leading "./", "/", or glob) would otherwise never match
        # anything -- silently checking zero files rather than failing.
        case "$path" in
        ./* | /* | \**) ;;
        *) path="./${path}" ;;
        esac

        if [ $is_first -ne 1 ]; then
            cmd+="-o "
        fi
        cmd+="-path \"${path}\" "
        is_first=0
    done
    cmd+=" \)"

    echo "${cmd}"

    unset IFS
}


function check_file() {
    local file="$1"
    message="$(${CLANG_FORMAT} -n -Werror --ferror-limit=3 --style=file --fallback-style=LLVM "${file}")"
    local status="$?"
    if [ $status -ne 0 ]; then
        echo "$message" >&2
        return 1
    fi
    return 0
}


function main() {
    local input_pattern=$1
    echo -e "Sources: $input_pattern"
    local cmd="$(find_cmd "${input_pattern}")"
    local -a issues=()
    local checked=0

    for file in $(eval $cmd); do
        checked=$((checked + 1))
        echo -e "Checking file: $file"
        check_file "$file"
        if [ $? -ne 0 ]; then
            issues+=("$file")
        fi
    done

    if [ $checked -eq 0 ]; then
        echo -e "No files matched \"$input_pattern\" -- nothing was checked." >&2
        exit 1
    fi

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
            echo -n "${CLANG_FORMAT} --style=file -i "${issues[$i]}""
        done
        echo
        exit 1
    fi
}


main "${1:-*.c,*.h,*.cpp,*.hpp}"

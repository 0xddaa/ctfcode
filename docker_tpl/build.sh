#!/bin/bash

workdir="$( cd "$(dirname "$0")" ; pwd -P )"

if [ -z "$1" ]; then
    echo 'Usage: ./build.sh [binary_path]'
    exit 1
fi

problem=$(basename "$1")

find "$workdir" -type f -exec sed -i "s/PROBLEM/$problem/g" {} \;
echo "FLAG{this_is_the_flag_for_$problem}" > "$workdir/share/flag"
cp "$1" "$workdir/share/"
chmod u+x "$workdir/share/$problem"
docker-compose -f "$workdir/docker-compose.yml" up -d

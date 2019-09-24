#!/bin/bash

workdir="$( cd "$(dirname "$0")" ; pwd -P )"

if [ -z "$1" ]; then
    echo 'Usage: ./build.sh [binary_path] <tags>'
    exit 1
fi

problem=$(basename "$1")
[ -z "$2" ] && tag=latest || tag="$2"

find "$workdir" -type f -exec sed -i "s/PROBLEM/$problem/g" {} \;
sed -i "s/TAG/$tag/g" "$workdir/Dockerfile"
echo "FLAG{this_is_the_flag_for_$problem}" > "$workdir/share/flag"
cp "$1" "$workdir/share/"
chmod u+x "$workdir/share/$problem"
docker-compose -f "$workdir/docker-compose.yml" up -d

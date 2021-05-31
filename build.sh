#!/bin/bash

GREEN=''
NC=''

OUTPUT="chipvpn"

compile() {
	rep='.o'

	for d in ./*.c; do
		echo "$GREEN[Compiling] $NC $d"
	    gcc -Ofast -Wextra -Wall -c -o bin/$(echo $(basename "$d") | sed "s/\.c/$rep/") $d
	done

	echo "$GREEN[Linking] $NC $( ls ./bin/* )";

	if [[ "$OSTYPE" == "linux-gnu"* ]]; then
		gcc -o bin/$OUTPUT bin/*.o -Ofast -Wextra -Wall
	else
		echo "unknown OS"
	fi
}

run() {
	./bin/$OUTPUT
}

clean() {
	rm -rf build/*
}

"$@"
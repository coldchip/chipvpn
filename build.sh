#!/bin/sh

GREEN='\033[0;32m'
NC='\033[0m'

OUTPUT="chipvpn"

compile() {
	rep='.o'

	for d in ./*.c; do
		echo "$GREEN[Compiling] $NC $d"
	    gcc -Ofast -Wextra -Wall -c -o bin/$(echo $(basename "$d") | sed "s/\.c/$rep/") $d
	done

	for d in ./json/*.c; do
		echo "$GREEN[Compiling] $NC $d"
	    gcc -Ofast -Wextra -Wall -c -o bin/$(echo $(basename "$d") | sed "s/\.c/$rep/") $d
	done

	echo "$GREEN[Linking] $NC $( ls ./bin/* )"

	gcc -o bin/$OUTPUT bin/*.o -Ofast -Wextra -Wall
}

run() {
	./bin/$OUTPUT
}

clean() {
	rm -rf build/*
}

"$@"
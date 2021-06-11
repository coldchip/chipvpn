#!/bin/bash

GREEN=''
NC=''

OUTPUT="chipvpn"

compile() {
	rep='.o'

	for d in ./*.c; do
		echo "$GREEN[Compiling] $NC $d"
	    gcc -Ofast -Wall -c -o bin/$(echo $(basename "$d") | sed "s/\.c/$rep/") $d
	done

	echo "$GREEN[Linking] $NC $( ls ./bin/* )";

	gcc -o bin/$OUTPUT bin/*.o -Ofast -Wall
}

run() {
	./bin/$OUTPUT
}

clean() {
	rm -rf build/*
}

"$@"
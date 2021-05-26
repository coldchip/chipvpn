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

	if [[ "$OSTYPE" == "linux-gnu"* ]]; then
			gcc -o bin/$OUTPUT bin/*.o -Ofast -Wextra -Wall
	elif [[ "$OSTYPE" == "darwin"* ]]; then
			echo "unsuported OS"
	elif [[ "$OSTYPE" == "cygwin" ]]; then
			gcc -o bin/$OUTPUT bin/*.o -Ofast -Wextra -Wall
	elif [[ "$OSTYPE" == "msys" ]]; then
			gcc -o bin/$OUTPUT bin/*.o -Ofast -Wextra -Wall -lws2_32 -liphlpapi
	elif [[ "$OSTYPE" == "win32" ]]; then
			echo "unsuported OS"
	elif [[ "$OSTYPE" == "freebsd"* ]]; then
			echo "unsuported OS"
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
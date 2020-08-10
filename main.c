#include <stdio.h>
#include <string.h>
#include "chipvpn.h"

int main(int argc, char const *argv[]) {
	setbuf(stdout, NULL);
	printf("\e[1;1H\e[2J");
	console_log("ColdChip ChipVPN");
	if(argv[1] != NULL) {
		if(strcmp(argv[1], "client") == 0) {
			init_core(true);
		} else if(strcmp(argv[1], "server") == 0) {
			init_core(false);
		} else {
			printf("Invalid Argument\n");
		}
	} else {
		printf("%s\n", "usage: client or server");
	}
	return 0;
}
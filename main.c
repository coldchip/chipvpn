#include <stdio.h>
#include <string.h>
#include "chipvpn.h"

int main(int argc, char const *argv[]) {
	setbuf(stdout, NULL);
	//srand((unsigned) time(NULL));
	printf("\e[1;1H\e[2J");
	console_log("ColdChip ChipVPN");
	if(argv[1] != NULL) {
		if(strcmp(argv[1], "genkey") == 0) {
			printf("Unavailable\n");
		} else {
			run_core((char*)argv[1]);
		}
		
	} else {
		console_log("Usage: $ %s config.conf", argv[0]);
	}
	return 0;
}
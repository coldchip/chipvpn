#include <stdio.h>
#include <string.h>
#include "chipvpn.h"

int main(int argc, char const *argv[]) {
	setbuf(stdout, NULL);
	printf("\e[1;1H\e[2J");
	console_log("ColdChip ChipVPN");
	if(argv[1] != NULL) {
		
		run_core((char*)argv[1]);
		
	} else {
		printf("Usage %s config.conf\n", argv[0]);
	}
	return 0;
}
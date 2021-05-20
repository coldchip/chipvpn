#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include "event.h"
#include "chipvpn.h"

int main(int argc, char const *argv[]) {
	if(argc > 0) {
		setbuf(stdout, NULL);
		srand((unsigned) time(NULL));
		if(argv[1] != NULL) {
			if(strcmp(argv[1], "genkey") == 0) {
				printf("Unavailable\n");
			} else {
				chipvpn_event_loop((char*)argv[1]);
			}
			
		} else {
			console_log("Usage: $ %s config.conf", argv[0]);
		}
		return 0;
	}
}
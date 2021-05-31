#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include "event.h"
#include "config.h"
#include "chipvpn.h"

int main(int argc, char const *argv[]) {
	if(argc > 0) {
		setbuf(stdout, NULL);
		srand((unsigned) time(NULL));
		if(argv[1] != NULL) {
			if(strcmp(argv[1], "genkey") == 0) {
				char key[16];
				chipvpn_generate_random(key, sizeof(key));
				for(int i = 0; i < (int)sizeof(key); i++) {
					printf("%02x", key[i] & 0xFF);
				}
				printf("\n");
			} else {
				ChipVPNConfig *config = chipvpn_load_config((char*)argv[1]);
				if(!config) {
					error("unable to read config");
				}
				console_log("ColdChip ChipVPN v%i", VERSION);
				chipvpn_event_loop(config);
				chipvpn_free_config(config);
			}
			
		} else {
			console_log("Usage: $ %s config.conf", argv[0]);
		}
		return 0;
	}
}
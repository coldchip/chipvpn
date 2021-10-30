/*
 * ColdChip ChipVPN
 *
 * Copyright (c) 2016-2021, Ryan Loh <ryan@coldchip.ru>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README for more details.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include "event.h"
#include "config.h"
#include "chipvpn.h"

void on_status_change(ChipVPNStatus status) {
	console_log("changed status: %i", status);
}

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
				ChipVPNConfig config;
				if(!chipvpn_load_config(&config, (char*)argv[1])) {
					error("unable to read config");
				}
				console_log("ColdChip ChipVPN v%i", CHIPVPN_VERSION);
				chipvpn_event_loop(&config, on_status_change);
			}
		} else {
			console_log("Usage: $ %s config.conf", argv[0]);
		}
		return 0;
	}
}
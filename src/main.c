/*
 * ColdChip ChipVPN
 *
 * Copyright (c) 2016-2021, Ryan Loh <ryan@chip.sg>
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

#include "event.h"
#include "chipvpn.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/rand.h>

int main(int argc, const char *argv[]) {
	chipvpn_log("ColdChip ChipVPN v%i", CHIPVPN_VERSION);
	if(argc > 0) {
		setbuf(stdout, NULL);
		srand((unsigned) time(NULL));
		if(argv[1] != NULL) {
			if(strcmp(argv[1], "genkey") == 0) {
				unsigned char key[16];
				RAND_priv_bytes(key, sizeof(key));
				for(int i = 0; i < (int)sizeof(key); i++) {
					printf("%02x", key[i] & 0xFF);
				}
				printf("\n"); 
			} else {
				chipvpn_init((char*)argv[1]);
			}
		} else {
			chipvpn_log("Usage: $ %s config.json", argv[0]);
		}
		return 0;
	}
}
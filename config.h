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

#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

typedef enum {
	MODE_SERVER,
	MODE_CLIENT
} VPNMode;

typedef struct _ChipVPNConfig {
	char     ip[1024];
	int      port;
	char     token[1024];
	VPNMode  mode;
	bool     pull_routes;
	int      max_peers;
	char     gateway[32];
	char     subnet[32];
} ChipVPNConfig;

bool     chipvpn_load_config(ChipVPNConfig *config, char *config_file);
void     chipvpn_load_default_config(ChipVPNConfig *config);

#endif
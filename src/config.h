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

#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>
#include <netinet/in.h>
#include "list.h"

typedef enum {
	MODE_SERVER,
	MODE_CLIENT
} VPNMode;

typedef struct _VPNConfigRoute {
	ListNode node;
	struct in_addr src;
	struct in_addr mask;
} VPNConfigRoute;

typedef struct _VPNConfig {
	VPNMode  mode;
	char     ip[1024];
	int      port;
	char     token[512];
	bool     pull_routes;
	List     push_routes;
	int      max_peers;
	char     gateway[32];
	char     subnet[32];
	int      mtu;
	int      sendbuf;
	int      recvbuf;
	int      qlen;
} VPNConfig;

VPNConfig          *chipvpn_config_create();
bool                chipvpn_config_load(VPNConfig *config, const char *config_file);
void                chipvpn_config_reset(VPNConfig *config);
void                chipvpn_config_free(VPNConfig *config);

#endif
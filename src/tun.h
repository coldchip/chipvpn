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

#ifndef TUN_H
#define TUN_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include "chipvpn.h"

typedef struct _VPNTun {
	char dev[128];
	int fd;
} VPNTun;

VPNTun       *chipvpn_tun_create(const char *dev);
bool          chipvpn_tun_setip(VPNTun* tun, struct in_addr ip, struct in_addr mask, int mtu, int qlen);
bool          chipvpn_tun_ifup(VPNTun *tun);
void          chipvpn_tun_free(VPNTun *tun);

#endif
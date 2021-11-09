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

#ifndef TUN_H
#define TUN_H

#include <stdint.h>
#include <stdbool.h>

typedef struct _Tun {
	char dev[128];
	int fd;
} Tun;

Tun *chipvpn_tun_open(char *dev);
bool chipvpn_tun_setip(Tun *tun, uint32_t ip, uint32_t mask, int mtu);
bool chipvpn_tun_ifup(Tun *tun);
void chipvpn_tun_free(Tun *tun);

#endif
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

#ifndef CHIPVPN_H
#define CHIPVPN_H

#include "packet.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#define CHIPVPN_VERSION 10000073L

char              *chipvpn_read_file(const char *file);
char              *chipvpn_strdup(const char *s);
void               chipvpn_log(const char *format, ...);
void               chipvpn_warn(const char *format, ...);
void               chipvpn_error(const char *format, ...);
char              *chipvpn_resolve_hostname(const char *ip);
char              *chipvpn_format_bytes(uint64_t bytes);
bool               chipvpn_cidr_to_mask(const char *cidr, uint32_t *ip, uint32_t *mask);
uint32_t           chipvpn_get_time();
bool               chipvpn_get_gateway(struct in_addr *gateway, char *dev);

#endif
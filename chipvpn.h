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

#ifndef CHIPVPN_H
#define CHIPVPN_H

#include "packet.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#define CHIPVPN_VERSION 10000002L
#define CHIPVPN_MAX_MTU 1500

char              *read_file_into_buffer(char *file);
struct in_addr     get_default_gateway();
int                exec_sprintf(char *format, ...);
void               msg_log(VPNPacketType type);
void               warning_log(char *format, ...);
void               error(char *format, ...);
void               console_log(char *format, ...);
uint16_t           chipvpn_checksum16(void *data, unsigned int bytes);
char              *chipvpn_resolve_hostname(char *ip);
void               chipvpn_generate_random(char *buf, int len);
char              *chipvpn_format_bytes(uint64_t bytes);
uint32_t           chipvpn_get_time();

#endif
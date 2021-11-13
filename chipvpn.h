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

#ifndef CHIPVPN
#define CHIPVPN

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#define CHIPVPN_VERSION         1000000088L
#define CHIPVPN_MAX_MTU         1500
#define CHIPVPN_MAX_PACKET_SIZE 4096

#if CHIPVPN_MAX_MTU > CHIPVPN_MAX_PACKET_SIZE
	#error "CHIPVPN_MAX_MTU < CHIPVPN_MAX_PACKET_SIZE"
#endif

char              *read_file_into_buffer(char *file);
struct in_addr     get_default_gateway();
int                exec_sprintf(char *format, ...);
void               warning(char *format, ...);
void               error(char *format, ...);
void               console_log(char *format, ...);
char              *chipvpn_malloc_fmt(char *format, ...);
uint16_t           chipvpn_checksum16(void *data, unsigned int bytes);
char              *chipvpn_resolve_hostname(char *ip);
void               chipvpn_generate_random(char *buf, int len);
const char        *chipvpn_format_bytes(uint64_t bytes);
uint32_t           chipvpn_get_time();
int                chipvpn_set_socket_non_block(int fd);

#ifdef __cplusplus
}
#endif

#endif
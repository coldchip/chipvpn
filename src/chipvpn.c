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

#include "chipvpn.h"
#include "packet.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h> 
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>

char *chipvpn_read_file(const char *file) {
	FILE *infp = fopen(file, "rb");
	if (!infp) {
		return NULL;
	}
	fseek(infp, 0, SEEK_END);
	long fsize = ftell(infp);
	char *p = malloc(fsize + 1);
	fseek(infp, 0, SEEK_SET);

	if(fread((char*)p, 1, fsize, infp)) {}

	fclose(infp);
	*(p + fsize) = '\0';

	return p;
}

bool chipvpn_get_gateway(struct in_addr *addr) {
	char ip_addr[16];
	char cmd[] = "ip route show default | awk '/default/ {print $3}' |  tr -cd '[a-zA-Z0-9]._-'";
	FILE* fp = popen(cmd, "r");

	if(fgets(ip_addr, 16, fp) != NULL){
		//printf("%s\n", line);
	}
	pclose(fp);
	ip_addr[15] = '\0';

	inet_aton(ip_addr, addr);
	return true;
}

int chipvpn_execf(const char *format, ...) {
	va_list args;
	va_start(args, format);

	char fmt[1000];

	vsnprintf(fmt, sizeof(fmt), format, args);

	int res = system(fmt);
	
	va_end(args);

	return res;
}

void chipvpn_log(const char *format, ...) {
	va_list args;
	va_start(args, format);

	char template[] = "\033[0;32m[ChipVPN] %s\033[0m\n";

	int i = snprintf(NULL, 0, template, format);
	char *fmt = malloc(i + 1);
	sprintf(fmt, template, format);
	vprintf(fmt, args);
	free(fmt);
	
	va_end(args);
}

void chipvpn_warn(const char *format, ...) {
	va_list args;
	va_start(args, format);

	char template[] = "\033[0;31m[ChipVPN] %s\033[0m\n";

	int i = snprintf(NULL, 0, template, format);
	char *fmt = malloc(i + 1);
	sprintf(fmt, template, format);
	vprintf(fmt, args);
	free(fmt);
	
	va_end(args);
}

void chipvpn_error(const char *format, ...) {
	va_list args;
	va_start(args, format);

	char template[] = "\033[0;31m[ChipVPN] %s\033[0m\n";

	int i = snprintf(NULL, 0, template, format);
	char *fmt = malloc(i + 1);
	sprintf(fmt, template, format);
	vprintf(fmt, args);
	free(fmt);
	
	va_end(args);

	exit(1);
}

uint16_t chipvpn_checksum16(void *data, unsigned int bytes) {
	uint16_t *data_pointer = (uint16_t *) data;
	uint32_t total_sum = 0;

	while(bytes > 1) {
		total_sum += *data_pointer++;
		//If it overflows to the MSBs add it straight away
		if(total_sum >> 16){
			total_sum = (total_sum >> 16) + (total_sum & 0x0000FFFF);
		}
		bytes -= 2; //Consumed 2 bytes
	}
	if(1 == bytes) {
		//Add the last byte
		total_sum += *(((uint8_t *) data_pointer) + 1);
		//If it overflows to the MSBs add it straight away
		if(total_sum >> 16){
			total_sum = (total_sum >> 16) + (total_sum & 0x0000FFFF);
		}
		bytes -= 1;
	}

	return (~((uint16_t) total_sum));
}

char *chipvpn_resolve_hostname(const char *ip) {
	struct hostent *he = gethostbyname(ip);
	if(he == NULL) {
		return NULL;
	}
	struct in_addr *domain = ((struct in_addr **)he->h_addr_list)[0];
	if(domain == NULL) {
		return NULL;
	}
	return inet_ntoa(*domain);
}

void chipvpn_generate_random(unsigned char *buf, int len) {
	int fp = open("/dev/urandom", O_RDONLY);
	if(fp >= 0) {
		if(read(fp, buf, len) != len) {
			// something went wrong
		}
		close(fp);
	}
}

char *chipvpn_format_bytes(uint64_t bytes) {
	char *suffix[] = {"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB"};
	char length = sizeof(suffix) / sizeof(suffix[0]);

	int i = 0;
	double dblBytes = bytes;

	if (bytes > 1024) {
		for (i = 0; (bytes / 1024) > 0 && i < length - 1; i++, bytes /= 1024) {
			dblBytes = bytes / 1024.0;
		}
	}

	static char output[200];
	sprintf(output, "%.02lf %s", dblBytes, suffix[i]);
	return output;
}

bool chipvpn_cidr_to_mask(const char *cidr, uint32_t *ip, uint32_t *mask) {
	uint8_t a, b, c, d, bits;
	if (sscanf(cidr, "%hhu.%hhu.%hhu.%hhu/%hhu", &a, &b, &c, &d, &bits) < 5) {
	    return false; /* didn't convert enough of CIDR */
	}
	
	if (bits > 32) {
	    return false; /* Invalid bit count */
	}

	*ip = htonl(
	    (a << 24UL) |
	    (b << 16UL) |
	    (c << 8UL) |
	    (d << 0UL)
	);

	if(bits == 0) {
		*mask = 0;
	} else {
		*mask = htonl((0xFFFFFFFFUL << (32 - bits)) & 0xFFFFFFFFUL);
	}

	return true;
}

uint32_t chipvpn_get_time() {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000 + tv.tv_usec / 1000) / 1000;
}
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

char *read_file_into_buffer(char *file) {
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

uint32_t get_default_gateway() {
	char ip_addr[16];
	char cmd[] = "ip route show default | awk '/default/ {print $3}' |  tr -cd '[a-zA-Z0-9]._-'";
	FILE* fp = popen(cmd, "r");

	if(fgets(ip_addr, 16, fp) != NULL){
		//printf("%s\n", line);
	}
	pclose(fp);
	ip_addr[15] = '\0';
	return inet_addr(ip_addr);
}

int exec_sprintf(char *format, ...) {
	va_list args;
	va_start(args, format);

	char fmt[1000];

	vsnprintf(fmt, sizeof(fmt), format, args);

	int res = system(fmt);
	
	va_end(args);

	return res;
}

void console_log(char *format, ...) {
	va_list args;
	va_start(args, format);

	char fmt[1000];
	#ifdef __linux
		snprintf(fmt, sizeof(fmt), "\033[0;32m[ChipVPN] %s\033[0m\n", format);
	#else
		snprintf(fmt, sizeof(fmt), "[ChipVPN] %s\n", format);
	#endif
	vprintf(fmt, args);
	
	va_end(args);
}

void warning(char *format, ...) {
	va_list args;
	va_start(args, format);

	char fmt[1000];
	#ifdef __linux
		snprintf(fmt, sizeof(fmt), "\033[0;31m[ChipVPN] %s\033[0m\n", format);
	#else
		snprintf(fmt, sizeof(fmt), "[ChipVPN] %s\n", format);
	#endif
	vprintf(fmt, args);
	
	va_end(args);
}

void error(char *format, ...) {
	va_list args;
	va_start(args, format);

	char fmt[1000];
	#ifdef __linux
		snprintf(fmt, sizeof(fmt), "\033[0;31m[ChipVPN] %s\033[0m\n", format);
	#else
		snprintf(fmt, sizeof(fmt), "[ChipVPN] %s\n", format);
	#endif
	vprintf(fmt, args);
	
	va_end(args);
	exit(1);
}

char *chipvpn_malloc_fmt(char *format, ...) {
	va_list args;
	va_start(args, format);
	int len = vsnprintf(NULL, 0, format, args);
	va_end(args);
	
	va_start(args, format);
	char *result = malloc((len * sizeof(char)) + 1);
	vsnprintf(result, len + 1, format, args);
	va_end(args);

	return result;
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

char *chipvpn_resolve_hostname(char *ip) {
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

void chipvpn_generate_random(char *buf, int len) {
	int fp = open("/dev/urandom", O_RDONLY);
	if (fp >= 0) {
		int r = read(fp, buf, len);
		if (r < 0) {
			// something went wrong
		}
		close(fp);
	}
}

const char *chipvpn_format_bytes(uint64_t bytes) {
	char *suffix[] = {"B", "KB", "MB", "GB", "TB", "PB"};
	char length = sizeof(suffix) / sizeof(suffix[0]);

	int i = 0;
	double dblBytes = bytes;

	if (bytes > 1024) {
		for (i = 0; (bytes / 1024) > 0 && i < length-1; i++, bytes /= 1024) {
			dblBytes = bytes / 1024.0;
		}
	}

	static char output[200];
	sprintf(output, "%.02lf %s", dblBytes, suffix[i]);
	return output;
}

uint32_t chipvpn_get_time() {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000 + tv.tv_usec / 1000) / 1000;
}

int chipvpn_set_socket_non_block(int fd) {
	int flags = fcntl(fd, F_GETFL);
	if(flags == -1) {
		return -1;
	}

	if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0) {
		return 0;
	}

	return -1;
}
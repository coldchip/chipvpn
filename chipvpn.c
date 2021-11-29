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

char *read_file_into_buffer(const char *file) {
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

struct in_addr get_default_gateway() {
	char ip_addr[16];
	char cmd[] = "ip route show default | awk '/default/ {print $3}' |  tr -cd '[a-zA-Z0-9]._-'";
	FILE* fp = popen(cmd, "r");

	if(fgets(ip_addr, 16, fp) != NULL){
		//printf("%s\n", line);
	}
	pclose(fp);
	ip_addr[15] = '\0';

	struct in_addr in_gw;
	inet_aton(ip_addr, &in_gw);
	return in_gw;
}

int exec_sprintf(const char *format, ...) {
	va_list args;
	va_start(args, format);

	char fmt[1000];

	vsnprintf(fmt, sizeof(fmt), format, args);

	int res = system(fmt);
	
	va_end(args);

	return res;
}

void msg_log(VPNPacketType type) {
	switch(type) {
		case VPN_MSG_AUTH_ERROR: {
			warning_log("authentication error, invalid credentials [ERR_CODE::%i]", chipvpn_checksum16(&(int) { VPN_MSG_AUTH_ERROR }, sizeof(int)));
		}
		break;
		case VPN_MSG_AUTH_SUCCESS: {
			console_log("\033[0;34mauthentication success [CODE::%i]\033[0m", chipvpn_checksum16(&(int) { VPN_MSG_AUTH_SUCCESS }, sizeof(int)));
		}
		break;
		case VPN_MSG_UNAUTHORIZED: {
			warning_log("packet rejected, zone not authorized [ERR_CODE::%i]", chipvpn_checksum16(&(int) { VPN_MSG_UNAUTHORIZED }, sizeof(int)));
		}
		break;
		case VPN_MSG_DECRYPTION_ERROR: {
			warning_log("packet rejected, unable to decrypt packet [ERR_CODE::%i]", chipvpn_checksum16(&(int) { VPN_MSG_DECRYPTION_ERROR }, sizeof(int)));
		}
		break;
		case VPN_MSG_ENCRYPTION_ERROR: {
			warning_log("packet rejected, unable to encrypt packet [ERR_CODE::%i]", chipvpn_checksum16(&(int) { VPN_MSG_ENCRYPTION_ERROR }, sizeof(int)));
		}
		break;
		case VPN_MSG_PACKET_OVERSIZE: {
			warning_log("packet rejected, invalid packet size [ERR_CODE::%i]", chipvpn_checksum16(&(int) { VPN_MSG_PACKET_OVERSIZE }, sizeof(int)));
		}
		break;
		case VPN_MSG_PACKET_UNKNOWN: {
			warning_log("packet rejected, invalid packet received [ERR_CODE::%i]", chipvpn_checksum16(&(int) { VPN_MSG_PACKET_UNKNOWN }, sizeof(int)));
		}
		break;
		case VPN_MSG_ASSIGN_EXHAUSTED: {
			warning_log("unable to allocate ip address [ERR_CODE::%i]", chipvpn_checksum16(&(int) { VPN_MSG_ASSIGN_EXHAUSTED }, sizeof(int)));
		}
		break;
		case VPN_MSG_PEER_TIMEOUT: {
			warning_log("peer timeout [ERR_CODE::%i]", chipvpn_checksum16(&(int) { VPN_MSG_PEER_TIMEOUT }, sizeof(int)));
		}
		break;
		case VPN_MSG_QUOTA_EXCEEDED: {
			warning_log("peer quota exceeded, contact the server administrator [ERR_CODE::%i]", chipvpn_checksum16(&(int) { VPN_MSG_QUOTA_EXCEEDED }, sizeof(int)));
		}
		break;
		default: {
			warning_log("unknown error [ERR_CODE::%i]", chipvpn_checksum16(&type, sizeof(int)));
		}
		break;
	}
}

void warning_log(const char *format, ...) {
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

void error(const char *format, ...) {
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

void console_log(const char *format, ...) {
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
	if (fp >= 0) {
		if (read(fp, buf, len) != len) {
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

bool cidr_to_ip_and_mask(const char *cidr, uint32_t *ip, uint32_t *mask) {
	uint8_t a, b, c, d, bits;
	if (sscanf(cidr, "%hhu.%hhu.%hhu.%hhu/%hhu", &a, &b, &c, &d, &bits) < 5) {
	    return false; /* didn't convert enough of CIDR */
	}
	if (bits > 32) {
	    return false; /* Invalid bit count */
	}
	*ip =
	    (d << 24UL) |
	    (c << 16UL) |
	    (b << 8UL) |
	    (a << 0UL);
	*mask = (0xFFFFFFFFUL << (32 - bits)) & 0xFFFFFFFFUL;
	return true;
}

uint32_t chipvpn_get_time() {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000 + tv.tv_usec / 1000) / 1000;
}
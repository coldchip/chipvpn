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

#include <sys/ioctl.h>
#include <netinet/in.h>
#include <errno.h>
#include <net/route.h>

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

char *chipvpn_read_file(const char *file) {
	FILE *infp = fopen(file, "rb");
	if(!infp) {
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

char *chipvpn_strdup(const char *s) {
	size_t len = strlen(s) + 1;
	void *new = malloc(len);
	if(new == NULL) {
		return NULL;
	}
	return (char *)memcpy(new, s, len);
}

void chipvpn_log(const char *format, ...) {
	va_list args;
	va_start(args, format);

	printf("\033[0;32m[ChipVPN] ");
	vprintf(format, args);
	printf("\033[0m\n");
	
	va_end(args);
}

void chipvpn_warn(const char *format, ...) {
	va_list args;
	va_start(args, format);

	printf("\033[0;31m[ChipVPN] ");
	vprintf(format, args);
	printf("\033[0m\n");
	
	va_end(args);
}

void chipvpn_error(const char *format, ...) {
	va_list args;
	va_start(args, format);

	printf("\033[0;31m[ChipVPN] ");
	vprintf(format, args);
	printf("\033[0m\n");

	exit(1);
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

/*
	code to convert cidr ip string to ip and mask
	referenced from: https://stackoverflow.com/questions/63511698/is-this-fastes-way-to-check-if-ip-string-belongs-to-cidr-string
*/

bool chipvpn_cidr_to_mask(const char *cidr, uint32_t *ip, uint32_t *mask) {
	uint8_t a, b, c, d, bits;
	if(sscanf(cidr, "%hhu.%hhu.%hhu.%hhu/%hhu", &a, &b, &c, &d, &bits) < 5) {
	    return false; /* didn't convert enough of CIDR */
	}
	
	if(bits > 32) {
	    return false; /* Invalid bit count */
	}

	*ip = htonl((a << 24UL) | (b << 16UL) | (c << 8UL) | (d << 0UL));

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

/*
	code to grab the default gateway in linux using netlink
	referenced from: https://gist.github.com/javiermon/6272065
*/
bool chipvpn_get_gateway(struct in_addr *gateway, char *dev) {
	int     received_bytes = 0, msg_len = 0, route_attribute_len = 0;
	int     sock = -1, msgseq = 0;
	struct  nlmsghdr *nlh, *nlmsg;
	struct  rtmsg *route_entry;
	// This struct contain route attributes (route type)
	struct  rtattr *route_attribute;
	char    msgbuf[4096], buffer[4096];
	char    *ptr = buffer;
	struct  timeval tv;

	if((sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0) {
		return false;
	}

	memset(msgbuf, 0, sizeof(msgbuf));
	memset(buffer, 0, sizeof(buffer));

	/* point the header and the msg structure pointers into the buffer */
	nlmsg = (struct nlmsghdr*)msgbuf;

	/* Fill in the nlmsg header*/
	nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	nlmsg->nlmsg_type = RTM_GETROUTE; // Get the routes from kernel routing table .
	nlmsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST; // The message is a request for dump.
	nlmsg->nlmsg_seq = msgseq++; // Sequence of the message packet.
	nlmsg->nlmsg_pid = getpid(); // PID of process sending the request.

	/* 1 Sec Timeout to avoid stall */
	tv.tv_sec = 1;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (struct timeval*)&tv, sizeof(struct timeval));
	/* send msg */
	if(send(sock, nlmsg, nlmsg->nlmsg_len, 0) < 0) {
		close(sock);
		return false;
	}

	/* receive response */
	do {
		received_bytes = recv(sock, ptr, sizeof(buffer) - msg_len, 0);
		if(received_bytes < 0) {
			close(sock);
			return false;
		}

		nlh = (struct nlmsghdr*) ptr;

		/* Check if the header is valid */
		if((NLMSG_OK(nlmsg, received_bytes) == 0) || (nlmsg->nlmsg_type == NLMSG_ERROR)) {
		    close(sock);
			return false;
		}

		/* If we received all data break */
		if(nlh->nlmsg_type == NLMSG_DONE) {
		    break;
		} else {
		    ptr += received_bytes;
		    msg_len += received_bytes;
		}

		/* Break if its not a multi part message */
		if((nlmsg->nlmsg_flags & NLM_F_MULTI) == 0) {
		    break;
		}
	} while((nlmsg->nlmsg_seq != msgseq) || (nlmsg->nlmsg_pid != getpid()));

	/* parse response */
	for(; NLMSG_OK(nlh, received_bytes); nlh = NLMSG_NEXT(nlh, received_bytes)) {
		/* Get the route data */
		route_entry = (struct rtmsg*)NLMSG_DATA(nlh);

		/* We are just interested in main routing table */
		if(route_entry->rtm_table != RT_TABLE_MAIN) {
			continue;
		}

		route_attribute = (struct rtattr*)RTM_RTA(route_entry);
		route_attribute_len = RTM_PAYLOAD(nlh);

		bool set_gateway = false;
		bool set_dev = false;

		/* Loop through all attributes */
		for(; RTA_OK(route_attribute, route_attribute_len); route_attribute = RTA_NEXT(route_attribute, route_attribute_len)) {
			switch(route_attribute->rta_type) {
				case RTA_OIF: {
					if_indextoname(*(int*)RTA_DATA(route_attribute), dev);
					set_dev = true;
				}
				break;
				case RTA_GATEWAY: {
					*gateway = *(struct in_addr*)RTA_DATA(route_attribute);
					set_gateway = true;
				}
				break;
				default:
				break;
			}
		}

		if(set_gateway && set_dev) {
			break;
		}
	}

	close(sock);
	return true;
}
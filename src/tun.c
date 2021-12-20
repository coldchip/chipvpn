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

#include "tun.h"
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "packet.h"
#include "chipvpn.h"
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <netinet/in.h>

VPNTun *chipvpn_tun_open(const char *dev) {
	struct ifreq ifr;

	char *clonedev = "/dev/net/tun";

	int fd = open(clonedev, O_RDWR);
	if(fd < 0) {
		return NULL;
	}

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	if(strlen(dev) > IFNAMSIZ) {
		error("Interface name too long");
	}

	if(*dev) {
		strcpy(ifr.ifr_name, dev);
	}

	if(ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
		close(fd);
		return NULL;
	}

	VPNTun *tun = malloc(sizeof(VPNTun));
	tun->fd = fd;
	strcpy(tun->dev, ifr.ifr_name);

	return tun;
}

bool chipvpn_tun_setip(VPNTun* tun, struct in_addr ip, struct in_addr mask, int mtu) {
	if(tun) {
		struct ifreq ifr;
		ifr.ifr_addr.sa_family = AF_INET;

		strcpy(ifr.ifr_name, tun->dev);

		struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;

		int fd = socket(AF_INET, SOCK_DGRAM, 0);

		addr->sin_addr.s_addr = ip.s_addr;
		ioctl(fd, SIOCSIFADDR, &ifr);

		addr->sin_addr.s_addr = mask.s_addr;
		ioctl(fd, SIOCSIFNETMASK, &ifr);

		ifr.ifr_mtu = mtu;
		ioctl(fd, SIOCSIFMTU, &ifr);

	    close(fd);
	    return true;
	}
	return false;
}

bool chipvpn_tun_ifup(VPNTun* tun) {
	if(tun) {
		struct ifreq ifr;
		ifr.ifr_addr.sa_family = AF_INET;

		strcpy(ifr.ifr_name, tun->dev);

		int fd = socket(AF_INET, SOCK_DGRAM, 0);

		ifr.ifr_flags |= IFF_UP;
		ioctl(fd, SIOCSIFFLAGS, &ifr);

	    close(fd);
	    return true;
	}
	return false;
}

void chipvpn_tun_free(VPNTun *tun) {
	if(tun) {
		if(*tun->dev != '\0') {
			struct ifreq ifr;
			ifr.ifr_addr.sa_family = AF_INET;

			strcpy(ifr.ifr_name, tun->dev);

			int fd = socket(AF_INET, SOCK_DGRAM, 0);

			ifr.ifr_flags = ifr.ifr_flags & ~IFF_UP;
			ioctl(fd, SIOCSIFFLAGS, &ifr);

		    close(fd);
		}
		close(tun->fd);
		free(tun);
	}
}
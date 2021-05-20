#include "tun.h"
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include "chipvpn.h"

Tun *open_tun(char *dev) {

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

	Tun *tun = malloc(sizeof(Tun));
	tun->fd = fd;
	tun->dev = malloc(strlen(ifr.ifr_name) + 1);
	strcpy(tun->dev, ifr.ifr_name);

	return tun;
}

void setifip(Tun* tun, uint32_t ip, uint32_t mask, int mtu) {

	if(tun) {
		struct ifreq ifr;
		ifr.ifr_addr.sa_family = AF_INET;

		strcpy(ifr.ifr_name, tun->dev);

		struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;

		int fd = socket(AF_INET, SOCK_DGRAM, 0);

		addr->sin_addr.s_addr = ip;
		ioctl(fd, SIOCSIFADDR, &ifr);

		addr->sin_addr.s_addr = mask;
		ioctl(fd, SIOCSIFNETMASK, &ifr);

		ifr.ifr_mtu = mtu;
		ioctl(fd, SIOCSIFMTU, &ifr);

	    close(fd);
	}
}

void ifup(Tun* tun) {
	if(tun) {
		struct ifreq ifr;
		ifr.ifr_addr.sa_family = AF_INET;

		strcpy(ifr.ifr_name, tun->dev);

		int fd = socket(AF_INET, SOCK_DGRAM, 0);

		ifr.ifr_flags |= IFF_UP;
		ioctl(fd, SIOCSIFFLAGS, &ifr);

	    close(fd);
	}
}

void free_tun(Tun *tun) {
	if(tun) {
		if(tun->dev) {
			free(tun->dev);
		}
		free(tun);
	}
}
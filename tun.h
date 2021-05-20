#ifndef TUN_H
#define TUN_H

#include <stdint.h>

typedef struct _Tun {
	char *dev;
	int fd;
} Tun;

Tun *open_tun(char *dev);
void setifip(Tun *tun, uint32_t ip, uint32_t mask, int mtu);
void ifup(Tun *tun);
void free_tun(Tun *tun);

#endif
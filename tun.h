#ifndef TUN_H
#define TUN_H

#include <stdint.h>
#include <stdbool.h>

typedef struct _Tun {
	char *dev;
	int fd;
} Tun;

Tun *open_tun(char *dev);
bool tun_setip(Tun *tun, uint32_t ip, uint32_t mask, int mtu);
bool tun_bringup(Tun *tun);
void free_tun(Tun *tun);

#endif
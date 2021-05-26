#ifndef TUN_H
#define TUN_H

#include <stdint.h>
#include <stdbool.h>
#ifdef _WIN32
	#include "wintun.h"
#endif

typedef struct _Tun {
	char *dev;
	int fd;
	#ifdef _WIN32
	WINTUN_ADAPTER_HANDLE adapter;
	WINTUN_SESSION_HANDLE session;
	#endif
} Tun;

Tun *open_tun(char *dev);
bool tun_setip(Tun *tun, uint32_t ip, uint32_t mask, int mtu);
bool tun_bringup(Tun *tun);
#ifdef _WIN32
void ReceivePackets(_Inout_ DWORD_PTR SessionPtr);
void SendPacket(Tun *tun, void *data, int size);
#endif
void free_tun(Tun *tun);

#endif
#ifndef TUN_H
#define TUN_H

#include <stdint.h>
#include <stdbool.h>
#include "wintun.h"

typedef struct _Tun {
	WINTUN_ADAPTER_HANDLE adapter;
	WINTUN_SESSION_HANDLE session;
} Tun;

Tun *open_tun(char *dev);
bool tun_setip(Tun *tun, uint32_t ip, uint32_t mask, int mtu);
bool tun_bringup(Tun *tun);
void ReceivePackets(_Inout_ DWORD_PTR SessionPtr);
void SendPacket(Tun *tun, void *data, int size);
void free_tun(Tun *tun);

#endif
#ifndef EVENT_H
#define EVENT_H

#include "peer.h"
#include "packet.h"
#ifdef _WIN32
	#include <windows.h>
#endif

#define SHA1LEN 20

#ifndef max
#define max(a,b) \
({ __typeof__ (a) _a = (a); \
__typeof__ (b) _b = (b); \
_a > _b ? _a : _b; })
#endif

void chipvpn_load_config(char *config_file);
void chipvpn_event_loop(char *config);
void chipvpn_socket_event(VPNPeer *peer, VPNPacket *packet);
void chipvpn_tun_event(VPNDataPacket *packet, int size);

#ifdef _WIN32
static BOOL WINAPI chipvpn_event_cleanup_windows(_In_ DWORD CtrlType);
#else
void chipvpn_event_cleanup_unix(int type);
#endif

#endif
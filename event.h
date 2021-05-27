#ifndef EVENT_H
#define EVENT_H

#include "peer.h"
#include "packet.h"
#include <windows.h>

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
void chipvpn_event_cleanup(int type);

#endif
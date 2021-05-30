#ifndef EVENT_H
#define EVENT_H

#include "peer.h"
#include "packet.h"
#include "config.h"

#ifndef max
#define max(a,b) \
({ __typeof__ (a) _a = (a); \
__typeof__ (b) _b = (b); \
_a > _b ? _a : _b; })
#endif

void chipvpn_event_loop(ChipVPNConfig *config);
void chipvpn_socket_event(ChipVPNConfig *config, VPNPeer *peer, VPNPacket *packet);
void chipvpn_tun_event(ChipVPNConfig *config, VPNDataPacket *packet, int size);
void chipvpn_event_cleanup(int type);

#endif
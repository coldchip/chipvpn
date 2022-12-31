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

#ifndef EVENT_H
#define EVENT_H

#include "peer.h"
#include "packet.h"
#include "config.h"
#include <stdint.h>

#define VALIDATE_PEER(condition) \
if(!(condition)) { \
    return VPN_CONNECTION_END; \
} \

void                  chipvpn_init(char *config_file);
void                  chipvpn_setup(char *config_file);
void                  chipvpn_loop();
void                  chipvpn_cleanup();

void                  chipvpn_ticker();

VPNPacketError        chipvpn_socket_event(VPNPeer *peer, VPNPacket *packet);

VPNPacketError        chipvpn_recv_cert(VPNPeer *peer);
VPNPacketError        chipvpn_recv_cert_reply(VPNPeer *peer, VPNCertPacket *packet, int size);

VPNPacketError        chipvpn_recv_key(VPNPeer *peer, VPNKeyPacket *packet, int size);
VPNPacketError        chipvpn_recv_key_reply(VPNPeer *peer);

VPNPacketError        chipvpn_recv_login(VPNPeer *peer, VPNAuthPacket *packet, int size);
VPNPacketError        chipvpn_recv_login_reply(VPNPeer *peer);

VPNPacketError        chipvpn_recv_assign(VPNPeer *peer);
VPNPacketError        chipvpn_recv_assign_reply(VPNPeer *peer, VPNDHCPPacket *packet, int size);

VPNPacketError        chipvpn_recv_route(VPNPeer *peer);
VPNPacketError        chipvpn_recv_route_reply(VPNPeer *peer, VPNRoutePacket *packet, int size);

VPNPacketError        chipvpn_recv_data(VPNPeer *peer, VPNDataPacket *packet, int size);

VPNPacketError        chipvpn_recv_ping(VPNPeer *peer);

VPNPacketError        chipvpn_recv_msg(VPNPeer *peer, VPNMsgPacket *packet, int size);

void                  chipvpn_disconnect_peer(VPNPeer *peer);
void                  chipvpn_exit(int type);

#endif
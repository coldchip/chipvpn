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

#include "event.h"
#include "tun.h"
#include "chipvpn.h"
#include "peer.h"
#include "packet.h"
#include "firewall.h"
#include "socket.h"
#include "config.h"
#include "cJSON.h"
#include "list.h"
#include <unistd.h>
#include <sys/types.h>
#include <stdbool.h>
#include <sys/time.h>
#include <sys/un.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <openssl/rand.h>

bool terminate = false;

VPNConfig *config = NULL;

VPNSocket *host = NULL;
VPNTun    *tun  = NULL;

void chipvpn_init(VPNConfig *c) {
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, chipvpn_exit);

	config = c;

	while(1) {
		chipvpn_setup();
		chipvpn_loop();
		chipvpn_cleanup();
		sleep(1);
	}
}

void chipvpn_setup() {
	terminate = false;

	tun = chipvpn_tun_create(NULL);
	if(tun == NULL) {
		chipvpn_error("tuntap adapter creation failed, please run as sudo");
	}

	host = chipvpn_socket_create();
	if(!host) {
		chipvpn_error("unable to create socket");
	}

	if(!chipvpn_socket_setopt_buffer(host, config->sendbuf, config->recvbuf)) {
		chipvpn_error("unable to change socket buffer size");
	}

	chipvpn_log("socket sndbuf [%i] rcvbuf [%i]", config->sendbuf, config->recvbuf);

	char *resolved = NULL;
	while(true) {
		resolved = chipvpn_resolve_hostname(config->ip);
		if(resolved) {
			break;
		}
		chipvpn_log("unable to resolve hostname, reconnecting");
		sleep(1);
	}
	strcpy(config->ip, resolved);

	if(config->mode == MODE_SERVER) {
		if(!chipvpn_socket_bind(host, config->ip, config->port)) {
			chipvpn_error("unable to bind");
		}
		chipvpn_log("server started on [%s:%i]", config->ip, config->port);

		struct in_addr subnet, gateway;

		inet_aton(config->subnet, &subnet);
		inet_aton(config->gateway, &gateway);

		if(!chipvpn_tun_setip(tun, gateway, subnet, config->mtu, config->qlen)) {
			chipvpn_error("unable to assign ip to tun adapter");
		}
		if(!chipvpn_tun_ifup(tun)) {
			chipvpn_error("unable to bring up tun adapter");
		}
	} else {
		chipvpn_log("connecting to [%s:%i]", config->ip, config->port);
		VPNPeer *peer = NULL;
		while(true) {
			peer = chipvpn_socket_connect(host, config->ip, config->port);
			if(peer) {
				break;
			}
			chipvpn_log("unable to connect, reconnecting");
		}
		
		VPNKeyPacket packet;
		RAND_priv_bytes((unsigned char*)&packet.key, sizeof(packet.key));
		chipvpn_peer_set_key(peer, packet.key);
		chipvpn_log("key exchange success");
		if(!chipvpn_peer_send(peer, VPN_TYPE_SET_KEY, &packet, sizeof(packet))) {
			chipvpn_peer_disconnect(peer);
			return;
		}

		chipvpn_peer_set_encryption(peer, true);

		VPNAuthPacket auth;
		strcpy((char*)auth.token, config->token);
		if(!chipvpn_peer_send(peer, VPN_TYPE_LOGIN, &auth, sizeof(auth))) {
			chipvpn_peer_disconnect(peer);
			return;
		}

	}
}

void chipvpn_loop() {
	int chipvpn_last_update = 0;
	struct timeval tv;

	fd_set rdset, wdset;

	while(!terminate) {
		tv.tv_sec = 0;
		tv.tv_usec = 200000;

		FD_ZERO(&rdset);
		FD_ZERO(&wdset);

		FD_SET(tun->fd, &rdset);
		
		int max = 0;
		max = MAX(max, tun->fd);

		if(config->mode == MODE_SERVER) {
			// listening socket for server accept
			FD_SET(host->fd, &rdset);
			max = MAX(max, host->fd);
		}

		/* 
			set fd
		*/
		for(ListNode *i = list_begin(&host->peers); i != list_end(&host->peers); i = list_next(i)) {
			VPNPeer *peer = (VPNPeer*)i;

			if(!chipvpn_peer_buffer_readable(peer) || list_size(&peer->inbound_queue) < 99) {
				FD_SET(peer->fd, &rdset);
			}
			if(!chipvpn_peer_buffer_writeable(peer) || list_size(&peer->outbound_queue) > 0) {
				FD_SET(peer->fd, &wdset);
			}

			max = MAX(max, peer->fd);
		}

		/*
			socket select
		*/
		if(select(max + 1, &rdset, &wdset, NULL, &tv) >= 0) {
			/* 
				ChipVPN's ticker
			*/
			if(chipvpn_get_time() - chipvpn_last_update >= 2) {
				chipvpn_ticker();
				chipvpn_last_update = chipvpn_get_time();
			}

			/* 
				Triggered when someone connects
			*/
			if(FD_ISSET(host->fd, &rdset) && config->mode == MODE_SERVER) {
				VPNPeer *peer = chipvpn_socket_accept(host);
				chipvpn_log("peer [%p] connected", peer);
			}

			/* 
				Triggered when the peer is readable/writable
			*/
			ListNode *i = list_begin(&host->peers);
			while(i != list_end(&host->peers)) {
				VPNPeer *peer = (VPNPeer*)i;
				i = list_next(i);
				// peer is readable
				if(FD_ISSET(peer->fd, &rdset)) {
					// read packet until it is a complete datagram
					int r = chipvpn_peer_dispatch_inbound(peer);
					if(r <= 0 && r != VPN_EAGAIN) {
						// peer I/O error
						chipvpn_peer_disconnect(peer);
						continue; // peer removed from list so skip the loop
					}

					chipvpn_peer_enqueue_service(peer);
				}

				// peer is writable
				if(FD_ISSET(peer->fd, &wdset)) {
					chipvpn_peer_dequeue_service(peer);

					int w = chipvpn_peer_dispatch_outbound(peer);
					if(w <= 0 && w != VPN_EAGAIN) {
						// peer I/O error
						chipvpn_peer_disconnect(peer);
						continue; // peer removed from list so skip the loop
					}
				}
			}

			/* 
				Triggered when the tunnel is readable
			*/
			if(FD_ISSET(tun->fd, &rdset)) {
				VPNDataPacket packet;
				int r = read(tun->fd, packet.data, sizeof(packet));
				if(r > 0) {
					IPPacket *ip_hdr = (IPPacket*)&packet.data;
					VPNPeer *peer = chipvpn_peer_get_by_ip(&host->peers, config->mode == MODE_SERVER ? ip_hdr->dst_addr : ip_hdr->src_addr);
					if(peer) {
						if(
							(chipvpn_peer_get_login(peer)) &&
							(chipvpn_firewall_match_rule(&peer->outbound_firewall, ip_hdr->dst_addr.s_addr))
						) {
							if(peer->tx >= peer->tx_max) {
								chipvpn_peer_disconnect(peer);
							}

							peer->tx += r;

							chipvpn_peer_send(peer, VPN_TYPE_DATA, &packet.data, r);
						}
					}
				}
			}
		}

		/* 
			Triggered when the peer's buffer has a fully constructed packet
		*/
		ListNode *j = list_begin(&host->peers);
		while(j != list_end(&host->peers)) {
			VPNPeer *peer = (VPNPeer*)j;
			j = list_next(j);

			VPNPacket packet;
			if(chipvpn_peer_recv(peer, &packet)) {
				if(chipvpn_socket_event(peer, &packet) == VPN_CONNECTION_END) {
					// event disconnection
					chipvpn_peer_disconnect(peer);
					continue; // peer removed from list so skip the loop
				}
			}
		}
	}
}

void chipvpn_cleanup() {
	if(host) {
		chipvpn_socket_free(host);
		host = NULL;
	}
	if(tun) {
		chipvpn_tun_free(tun);
		tun = NULL;
	}
}

/*
	function to periodically perform tasks related to maintaining connections with peers.
*/

void chipvpn_ticker() {
	if(config->mode == MODE_CLIENT && list_size(&host->peers) == 0) {
		chipvpn_log("reconnecting...");
		terminate = true;
	}

	ListNode *i = list_begin(&host->peers);
	while(i != list_end(&host->peers)) {
		VPNPeer *peer = (VPNPeer*)i;
		i = list_next(i);
		if(chipvpn_get_time() - peer->last_ping < 20) {
			if(chipvpn_peer_get_login(peer)) {
				if(!chipvpn_peer_send(peer, VPN_TYPE_PING, NULL, 0)) {
					chipvpn_log("disconnected peer due to ping failed");
					chipvpn_peer_disconnect(peer);
				}
			}
		} else {
			chipvpn_log("disconnected peer due to timeout");
			chipvpn_peer_disconnect(peer);
		}
	}
}

/*
	This function is a dispatcher for handling different types of packets received from a peer.
	The handling functions called by this function to perform various tasks, 
	such as setting keys, authenticating the peer, 
	assigning an IP address to the peer, 
	sending and receiving data, and responding to ping packets.
*/
VPNPacketError chipvpn_socket_event(VPNPeer *peer, VPNPacket *packet) {
	VPNPacketType type = (VPNPacketType)packet->header.type;
	VPNPacketBody data = packet->data;

	if(
		((type == VPN_TYPE_ASSIGN) ||
		(type == VPN_TYPE_ASSIGN_REPLY) || 
		(type == VPN_TYPE_DATA) || 
		(type == VPN_TYPE_PING)) && 
		(!chipvpn_peer_get_login(peer))
	) {
		// zones that require authentication
		return VPN_CONNECTION_END;
	}

	if(
		((type == VPN_TYPE_SET_KEY)      && 
		(config->mode != MODE_SERVER))   || 
		((type == VPN_TYPE_LOGIN)        && 
		(config->mode != MODE_SERVER))   ||
		((type == VPN_TYPE_LOGIN_REPLY)  && 
		(config->mode != MODE_CLIENT))   ||
		((type == VPN_TYPE_ASSIGN)       && 
		(config->mode != MODE_SERVER))   ||
		((type == VPN_TYPE_ASSIGN_REPLY) && 
		(config->mode != MODE_CLIENT))
	) {
		// mode specific zones
		return VPN_CONNECTION_END;
	}

	switch(type) {
		case VPN_TYPE_SET_KEY: {
			return chipvpn_recv_key(peer, &data.key_packet, PLEN(packet));
		}
		break;
		case VPN_TYPE_LOGIN: {
			return chipvpn_recv_login(peer, &data.auth_packet, PLEN(packet));
		}
		break;
		case VPN_TYPE_LOGIN_REPLY: {
			return chipvpn_recv_login_reply(peer);
		}
		break;
		case VPN_TYPE_ASSIGN: {
			return chipvpn_recv_assign(peer);
		}
		break;
		case VPN_TYPE_ASSIGN_REPLY: {
			return chipvpn_recv_assign_reply(peer, &data.dhcp_packet, PLEN(packet));
		}
		break;
		case VPN_TYPE_DATA: {
			return chipvpn_recv_data(peer, &data.data_packet, PLEN(packet));
		}
		break;
		case VPN_TYPE_PING: {
			return chipvpn_recv_ping(peer);
		}
		break;
		default: {
			return VPN_CONNECTION_END;
		}
		break;
	}
	return VPN_CONNECTION_END;
}

VPNPacketError chipvpn_recv_key(VPNPeer *peer, VPNKeyPacket *packet, int size) {
	chipvpn_log("key exchange success");
	chipvpn_peer_set_key(peer, packet->key);
	chipvpn_peer_set_encryption(peer, true);
	return VPN_PACKET_OK;
}

VPNPacketError chipvpn_recv_login(VPNPeer *peer, VPNAuthPacket *packet, int size) {
	if(memcmp(packet->token, config->token, strlen(config->token)) == 0) {
		chipvpn_peer_set_login(peer, true);

		if(!chipvpn_peer_send(peer, VPN_TYPE_LOGIN_REPLY, NULL, 0)) {
			return VPN_CONNECTION_END;
		}

		return VPN_PACKET_OK;
	} else {
		return VPN_CONNECTION_END;
	}

	return VPN_PACKET_OK;
}

VPNPacketError chipvpn_recv_login_reply(VPNPeer *peer) {
	chipvpn_peer_set_login(peer, true);

	if(!chipvpn_peer_send(peer, VPN_TYPE_ASSIGN, NULL, 0)) {
		return VPN_CONNECTION_END;
	}

	return VPN_PACKET_OK;
}

VPNPacketError chipvpn_recv_assign(VPNPeer *peer) {
	struct in_addr gateway;
	inet_aton(config->gateway, &gateway);

	if(!chipvpn_peer_get_free_ip(&host->peers, gateway, &peer->internal_ip)) {
		return VPN_CONNECTION_END;
	}

	VPNDHCPPacket assign = {
		.ip = peer->internal_ip.s_addr,
		.subnet = inet_addr(config->subnet),
		.gateway = inet_addr(config->gateway),
		.mtu = htonl(config->mtu)
	};

	if(!chipvpn_peer_send(peer, VPN_TYPE_ASSIGN_REPLY, &assign, sizeof(assign))) {
		return VPN_CONNECTION_END;
	}

	return VPN_PACKET_OK;
}

VPNPacketError chipvpn_recv_assign_reply(VPNPeer *peer, VPNDHCPPacket *packet, int size) {
	struct in_addr peer_ip, peer_subnet, peer_gateway;

	peer_ip.s_addr      = packet->ip;
	peer_subnet.s_addr  = packet->subnet;
	peer_gateway.s_addr = packet->gateway;
	uint32_t peer_mtu   = ntohl(packet->mtu);

	if(!chipvpn_tun_setip(tun, peer_ip, peer_subnet, peer_mtu, config->qlen)) {
		chipvpn_error("unable to assign ip to tunnel adapter");
	}
	if(!chipvpn_tun_ifup(tun)) {
		chipvpn_error("unable to bring up tunnel adapter");
	}

	char peer_ip_c[24];
	char peer_gateway_c[24];

	strcpy(peer_ip_c, inet_ntoa(peer_ip));
	strcpy(peer_gateway_c, inet_ntoa(peer_gateway));

	chipvpn_log("assigned dhcp: ip [%s] gateway [%s] mtu [%i] txqueuelen [%i]", peer_ip_c, peer_gateway_c, peer_mtu, config->qlen);

	if(config->pull_routes) {
		chipvpn_log("setting routes");

		struct in_addr default_gateway;
		if(!chipvpn_get_gateway(&default_gateway)) {
			chipvpn_error("unable to retrieve default gateway from system");
		}

		char default_gateway_c[24];
		strcpy(default_gateway_c, inet_ntoa(default_gateway));

		if(!chipvpn_execf("ip route add %s via %s", config->ip, default_gateway_c)) { }
		if(!chipvpn_execf("ip route add 0.0.0.0/1 via %s", peer_gateway_c)) { }
		if(!chipvpn_execf("ip route add 128.0.0.0/1 via %s", peer_gateway_c)) { }
	}

	peer->internal_ip = peer_ip;

	chipvpn_log("initialization sequence complete");
	return VPN_PACKET_OK;
}

VPNPacketError chipvpn_recv_data(VPNPeer *peer, VPNDataPacket *packet, int size) {
	IPPacket *ip_hdr = (IPPacket*)(&packet->data);
	if(
		(chipvpn_firewall_match_rule(&peer->inbound_firewall, ip_hdr->dst_addr.s_addr)) &&
		((ip_hdr->dst_addr.s_addr == peer->internal_ip.s_addr && config->mode == MODE_CLIENT) || 
		(ip_hdr->src_addr.s_addr == peer->internal_ip.s_addr && config->mode == MODE_SERVER))
	) {
		if(peer->rx >= peer->rx_max) {
			return VPN_CONNECTION_END;
		}
		peer->rx += size;
		if(write(tun->fd, packet->data, size) != size) {
			chipvpn_error("unable to write to tun adapter");
		}
	}
	return VPN_PACKET_OK;
}

VPNPacketError chipvpn_recv_ping(VPNPeer *peer) {
	char tx[50];
	char rx[50];
	strcpy(tx, chipvpn_format_bytes(peer->tx));
	strcpy(rx, chipvpn_format_bytes(peer->rx));
	chipvpn_log("heartbeat from peer [%p] tx: %s rx: %s", peer, tx, rx);

	peer->last_ping = chipvpn_get_time();
	return VPN_PACKET_OK; 
}

void chipvpn_exit(int type) {
	if(type == 0) {}
	chipvpn_cleanup();
	chipvpn_log("terminating");
	exit(0);
}
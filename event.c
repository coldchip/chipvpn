/*
 * ColdChip ChipVPN
 *
 * Copyright (c) 2016-2021, Ryan Loh <ryan@coldchip.ru>
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
#include "list.h"
#include <unistd.h>
#include <sys/types.h>
#include <stdbool.h>
#include <sys/time.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <openssl/rand.h>

bool terminate = false;

ChipVPNConfig *config = NULL;

VPNTun    *tun  = NULL;
VPNSocket *host = NULL;

struct timeval ping_stop, ping_start;

void chipvpn_init(ChipVPNConfig *c) {
	signal(SIGINT, chipvpn_exit);

	config = c;

	while(1) {
		chipvpn_setup();
		chipvpn_loop();
		sleep(1);
		chipvpn_cleanup();
	}
}

void chipvpn_setup() {
	terminate = false;

	tun = chipvpn_tun_open("");
	if(tun == NULL) {
		error("tuntap adapter creation failed, please run as sudo");
	}

	host = chipvpn_socket_create();
	if(host < 0) {
		error("unable to create socket");
	}

	char *resolved = NULL;
	while(true) {
		resolved = chipvpn_resolve_hostname(config->ip);
		if(resolved) {
			break;
		}
		console_log("unable to resolve hostname, reconnecting");
		sleep(1);
	}

	strcpy(config->ip, resolved);

	if(config->mode == MODE_SERVER) {
		if(!chipvpn_socket_bind(host, config->ip, config->port)) {
			error("unable to bind");
		}
		console_log("server started on [%s:%i]", config->ip, config->port);

		struct in_addr subnet, gateway;

		inet_aton(config->subnet, &subnet);
		inet_aton(config->gateway, &gateway);

		if(!chipvpn_tun_setip(tun, gateway, subnet, CHIPVPN_MAX_MTU)) {
			error("unable to assign ip to tun adapter");
		}
		if(!chipvpn_tun_ifup(tun)) {
			error("unable to bring up tun adapter");
		}
	} else {
		console_log("connecting to [%s:%i]", config->ip, config->port);
		VPNPeer *peer = NULL;
		while(true) {
			peer = chipvpn_socket_connect(host, config->ip, config->port);
			if(peer) {
				break;
			}
			console_log("unable to connect, reconnecting");
		}
		chipvpn_peer_send(peer, VPN_TYPE_SET_KEY, NULL, 0);
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

		for(ListNode *i = list_begin(&host->peers); i != list_end(&host->peers); i = list_next(i)) {
			VPNPeer *peer = (VPNPeer*)i;
			if(!chipvpn_peer_readable(peer)) {
				FD_SET(peer->fd, &rdset);
			}
			if(!chipvpn_peer_writeable(peer)) {
				FD_SET(peer->fd, &wdset);
			}
			max = MAX(max, peer->fd);
		}

		if(select(max + 1, &rdset, &wdset, NULL, &tv) >= 0) {
			/* 
				ChipVPN's service
			*/
			if(chipvpn_get_time() - chipvpn_last_update >= 1) {
				chipvpn_service();
				chipvpn_last_update = chipvpn_get_time();
			}

			/* 
				Triggered when someone connects
			*/
			if(config->mode == MODE_SERVER && FD_ISSET(host->fd, &rdset)) {
				chipvpn_socket_accept(host);
				console_log("connected");
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

					VPNPacket packet;
					if(chipvpn_peer_recv(peer, &packet) > 0) {
						chipvpn_socket_event(peer, &packet);
					}
				}

				// peer is writable
				if(FD_ISSET(peer->fd, &wdset)) {
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
				int r = read(tun->fd, (char*)&packet, sizeof(packet));
				if(r > 0) {
					chipvpn_tun_event(&packet, r);
				}
			}
		}
	}
}

void chipvpn_cleanup() {
	chipvpn_socket_free(host);
	chipvpn_tun_free(tun);
}

void chipvpn_service() {
	if(list_size(&host->peers) == 0 && config->mode == MODE_CLIENT) {
		console_log("reconnecting...");
		terminate = true;
	}

	ListNode *i = list_begin(&host->peers);
	while(i != list_end(&host->peers)) {
		VPNPeer *peer = (VPNPeer*)i;
		i = list_next(i);
		if(chipvpn_get_time() - peer->last_ping < 10) {
			if(chipvpn_peer_authed(peer)) {
				chipvpn_peer_send(peer, VPN_TYPE_PING, NULL, 0);
				gettimeofday(&ping_start, NULL);
			}
		} else {
			msg_log(VPN_MSG_PEER_TIMEOUT);
			chipvpn_peer_send(peer, VPN_MSG_PEER_TIMEOUT, NULL, 0);
			chipvpn_peer_disconnect(peer);
		}
	}
}

void chipvpn_socket_event(VPNPeer *peer, VPNPacket *packet) {
	VPNPacketType type = (VPNPacketType)(packet->header.type);
	VPNPacketBody data = packet->data;

	if(
		((type == VPN_TYPE_ASSIGN) || 
		(type == VPN_TYPE_DATA) || 
		(type == VPN_TYPE_PING) || 
		(type == VPN_TYPE_PONG)) && 
		(!chipvpn_peer_authed(peer))
	) {
		// zones that require authentication
		chipvpn_peer_send(peer, VPN_MSG_UNAUTHORIZED, NULL, 0);
		msg_log(VPN_MSG_UNAUTHORIZED);
		chipvpn_peer_disconnect(peer);
		return;
	}

	switch(type) {
		case VPN_TYPE_SET_KEY: {
			chipvpn_set_key_event(peer, &data.key_packet, PLEN(packet));
		}
		break;
		case VPN_TYPE_AUTH: {
			chipvpn_auth_event(peer, &data.auth_packet, PLEN(packet));
		}
		break;
		case VPN_TYPE_ASSIGN: {
			chipvpn_assign_event(peer, &data.dhcp_packet, PLEN(packet));
		}
		break;
		case VPN_TYPE_DATA: {
			chipvpn_data_event(peer, &data.data_packet, PLEN(packet));
		}
		break;
		case VPN_TYPE_PING: {
			chipvpn_ping_event(peer);
		}
		break;
		case VPN_TYPE_PONG: {
			chipvpn_pong_event(peer);
		}
		break;
		case VPN_MSG_AUTH_ERROR:
		case VPN_MSG_AUTH_SUCCESS:
		case VPN_MSG_UNAUTHORIZED:
		case VPN_MSG_DECRYPTION_ERROR:
		case VPN_MSG_ENCRYPTION_ERROR:
		case VPN_MSG_PACKET_OVERSIZE:
		case VPN_MSG_PACKET_UNKNOWN:
		case VPN_MSG_ASSIGN_EXHAUSTED:
		case VPN_MSG_PEER_TIMEOUT: {
			msg_log(type);
		}
		break;
		default: {
			chipvpn_peer_send(peer, VPN_MSG_PACKET_UNKNOWN, NULL, 0);
			msg_log(VPN_MSG_PACKET_UNKNOWN);
			chipvpn_peer_disconnect(peer);
		}
		break;
	}	
}

void chipvpn_set_key_event(VPNPeer *peer, VPNKeyPacket *packet, int size) {
	if(config->mode == MODE_SERVER) {
		console_log("key exchange success");
		VPNKeyPacket packet;
		RAND_priv_bytes((unsigned char*)&packet.key, sizeof(packet.key));
		chipvpn_set_key(peer, packet.key);
		chipvpn_peer_send(peer, VPN_TYPE_SET_KEY, &packet, sizeof(packet));
	} else {
		console_log("key exchange success");
		chipvpn_set_key(peer, packet->key);

		VPNAuthPacket auth, p_auth;
		strcpy(auth.token, config->token);

		if(!crypto_encrypt(peer->outbound_aes, &p_auth, &auth, sizeof(auth))) {
			msg_log(VPN_MSG_ENCRYPTION_ERROR);
			chipvpn_peer_send(peer, VPN_MSG_ENCRYPTION_ERROR, NULL, 0);
			chipvpn_peer_disconnect(peer);
			return;
		}

		chipvpn_peer_send(peer, VPN_TYPE_AUTH, &p_auth, sizeof(p_auth));
		return;
	}
}

void chipvpn_auth_event(VPNPeer *peer, VPNAuthPacket *packet, int size) {
	if(config->mode == MODE_SERVER) {
		if(size > sizeof(VPNAuthPacket)) {
			msg_log(VPN_MSG_PACKET_OVERSIZE);
			chipvpn_peer_send(peer, VPN_MSG_PACKET_OVERSIZE, NULL, 0);
			chipvpn_peer_disconnect(peer);
			return;
		}

		VPNAuthPacket auth;
		if(!crypto_decrypt(peer->inbound_aes, &auth, packet, size)) {
			msg_log(VPN_MSG_DECRYPTION_ERROR);
			chipvpn_peer_send(peer, VPN_MSG_DECRYPTION_ERROR, NULL, 0);
			chipvpn_peer_disconnect(peer);
			return;
		}

		if(memcmp(auth.token, config->token, strlen(config->token)) == 0) {
			chipvpn_peer_login(peer);
			
			msg_log(VPN_MSG_AUTH_SUCCESS);
			chipvpn_peer_send(peer, VPN_TYPE_AUTH, NULL, 0);
			return;
		} else {
			chipvpn_peer_logout(peer);

			msg_log(VPN_MSG_AUTH_ERROR);
			chipvpn_peer_send(peer, VPN_MSG_AUTH_ERROR, NULL, 0);
			chipvpn_peer_disconnect(peer);
			return;
		}
	} else {
		chipvpn_peer_login(peer);

		msg_log(VPN_MSG_AUTH_SUCCESS);
		chipvpn_peer_send(peer, VPN_TYPE_ASSIGN, NULL, 0);
		return;
	}
}

void chipvpn_assign_event(VPNPeer *peer, VPNAssignPacket *packet, int size) {
	if(config->mode == MODE_SERVER) {
		struct in_addr gateway;
		inet_aton(config->gateway, &gateway);

		if(!chipvpn_get_peer_free_ip(&host->peers, gateway, &peer->internal_ip)) {
			msg_log(VPN_MSG_ASSIGN_EXHAUSTED);
			chipvpn_peer_send(peer, VPN_MSG_ASSIGN_EXHAUSTED, NULL, 0);
			chipvpn_peer_disconnect(peer);
			return;
		}

		VPNAssignPacket assign, p_assign;
		assign.ip      = peer->internal_ip.s_addr;
		assign.subnet  = inet_addr(config->subnet);
		assign.gateway = inet_addr(config->gateway);
		assign.mtu     = htonl(CHIPVPN_MAX_MTU);

		if(!crypto_encrypt(peer->outbound_aes, &p_assign, &assign, sizeof(assign))) {
			msg_log(VPN_MSG_ENCRYPTION_ERROR);
			chipvpn_peer_send(peer, VPN_MSG_ENCRYPTION_ERROR, NULL, 0);
			chipvpn_peer_disconnect(peer);
			return;
		}

		chipvpn_peer_send(peer, VPN_TYPE_ASSIGN, &p_assign, sizeof(p_assign));
		return;
	} else {
		if(size > sizeof(VPNAssignPacket)) {
			msg_log(VPN_MSG_PACKET_OVERSIZE);
			chipvpn_peer_send(peer, VPN_MSG_PACKET_OVERSIZE, NULL, 0);
			chipvpn_peer_disconnect(peer);
			return;
		}

		VPNAssignPacket p_assign;
		if(!crypto_decrypt(peer->inbound_aes, &p_assign, packet, size)) {
			msg_log(VPN_MSG_DECRYPTION_ERROR);
			chipvpn_peer_send(peer, VPN_MSG_DECRYPTION_ERROR, NULL, 0);
			chipvpn_peer_disconnect(peer);
			return;
		}

		struct in_addr peer_ip, peer_subnet, peer_gateway;

		peer_ip.s_addr        = p_assign.ip;
		peer_subnet.s_addr    = p_assign.subnet;
		peer_gateway.s_addr   = p_assign.gateway;
		uint32_t peer_mtu     = ntohl(p_assign.mtu);

		if(!chipvpn_tun_setip(tun, peer_ip, peer_subnet, peer_mtu)) {
			error("unable to assign ip to tunnel adapter");
		}
		if(!chipvpn_tun_ifup(tun)) {
			error("unable to bring up tunnel adapter");
		}

		char peer_ip_c[24];
		char peer_gateway_c[24];

		strcpy(peer_ip_c, inet_ntoa(peer_ip));
		strcpy(peer_gateway_c, inet_ntoa(peer_gateway));

		console_log("assigned dhcp: ip [%s] gateway [%s]", peer_ip_c, peer_gateway_c);

		if(config->pull_routes) {
			console_log("setting routes");

			char default_gateway_c[24];
			strcpy(default_gateway_c, inet_ntoa(get_default_gateway()));

			if(exec_sprintf("ip route add %s via %s", config->ip, default_gateway_c)) { }
			if(exec_sprintf("ip route add 0.0.0.0/1 via %s", peer_gateway_c)) { }
			if(exec_sprintf("ip route add 128.0.0.0/1 via %s", peer_gateway_c)) { }
		}

		peer->internal_ip = peer_ip;
		peer->tx          = 0;
		peer->rx          = 0;
		console_log("initialization sequence complete");
		return;
	}
}

void chipvpn_data_event(VPNPeer *peer, VPNDataPacket *packet, int size) {
	if(size > sizeof(VPNDataPacket)) {
		msg_log(VPN_MSG_PACKET_OVERSIZE);
		chipvpn_peer_send(peer, VPN_MSG_PACKET_OVERSIZE, NULL, 0);
		chipvpn_peer_disconnect(peer);
		return;
	}

	VPNDataPacket p_data;
	if(!crypto_decrypt(peer->inbound_aes, &p_data, packet, size)) {
		msg_log(VPN_MSG_DECRYPTION_ERROR);
		chipvpn_peer_send(peer, VPN_MSG_DECRYPTION_ERROR, NULL, 0);
		chipvpn_peer_disconnect(peer);
		return;
	}
	
	IPPacket *ip_hdr = (IPPacket*)(&p_data.data);
	if(
		(validate_inbound_packet(ip_hdr)) &&
		((ip_hdr->dst_addr.s_addr == peer->internal_ip.s_addr && config->mode == MODE_CLIENT) || 
		(ip_hdr->src_addr.s_addr == peer->internal_ip.s_addr && config->mode == MODE_SERVER)) && 
		(size > 0 && size <= CHIPVPN_MAX_MTU)
	) {
		peer->rx += size;

		if(write(tun->fd, (char*)&p_data, size) != size) {
			error("unable to write to tun adapter");
		}
		return;
	}
}

void chipvpn_ping_event(VPNPeer *peer) {
	peer->last_ping = chipvpn_get_time();
	chipvpn_peer_send(peer, VPN_TYPE_PONG, NULL, 0);
	return;
}

void chipvpn_pong_event(VPNPeer *peer) {
	gettimeofday(&ping_stop, NULL);

	char tx[50];
	char rx[50];
	strcpy(tx, chipvpn_format_bytes(peer->tx));
	strcpy(rx, chipvpn_format_bytes(peer->rx));

	uint32_t peer_index = 0;
	for(ListNode *i = list_begin(&host->peers); i != list_end(&host->peers); i = list_next(i)) {
		if(peer == (VPNPeer*)i) {
			break;
		}
		++peer_index;
	}

	console_log("peer 0x%04x ping took %lu ms TX: %s RX: %s", peer_index, ((ping_stop.tv_sec - ping_start.tv_sec) * 1000000 + ping_stop.tv_usec - ping_start.tv_usec) / 1000, tx, rx); 
	return;
}

void chipvpn_tun_event(VPNDataPacket *packet, int size) {
	IPPacket *ip_hdr = (IPPacket*)(packet->data);

	VPNPeer *peer = chipvpn_get_peer_by_ip(&host->peers, config->mode == MODE_SERVER ? ip_hdr->dst_addr : ip_hdr->src_addr);
	if(
		(peer) && 
		(chipvpn_peer_authed(peer)) &&
		(validate_outbound_packet(ip_hdr)) &&
		(chipvpn_peer_writeable(peer))
	) {
		peer->tx += size;

		VPNDataPacket p_packet;
		if(!crypto_encrypt(peer->outbound_aes, &p_packet, packet, size)) {
			msg_log(VPN_MSG_ENCRYPTION_ERROR);
			chipvpn_peer_send(peer, VPN_MSG_ENCRYPTION_ERROR, NULL, 0);
			chipvpn_peer_disconnect(peer);
			return;
		}

		chipvpn_peer_send(peer, VPN_TYPE_DATA, &p_packet, size);
		return;
	}
}

void chipvpn_exit(int type) {
	if(type == 0) {}
	chipvpn_cleanup();
	console_log("terminating");
	exit(0);
}


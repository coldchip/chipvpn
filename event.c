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
#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h> 
#include <netinet/in.h>

bool quit = true;
bool retry = false;

Tun *tun = NULL;

List peers;

struct timeval ping_stop, ping_start;

void chipvpn_event_loop(ChipVPNConfig *config) {
	signal(SIGINT, chipvpn_exit);

	while(1) {
		quit = false;

		list_clear(&peers);

		tun = open_tun("");
		if(tun  == NULL) {
			error("tuntap adaptor creation failed, please run as sudo");
		}

		int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

		if(sock < 0) {
			error("unable to create socket");
		}

		if(chipvpn_set_socket_non_block(sock) < 0) {
			error("unable to set socket to non blocking mode");
		}

		if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &(char){1}, sizeof(int)) < 0){
			error("unable to call setsockopt");
		}
		if(setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &(char){1}, sizeof(int)) < 0){
			error("unable to call setsockopt");
		}

		char *resolved = chipvpn_resolve_hostname(config->ip);
		if(resolved == NULL) {
			console_log("unable to resolve hostname, reconnecting");
			goto chipvpn_cleanup;
		}

		strcpy(config->ip, resolved);

		if(config->mode == MODE_SERVER) {
			struct sockaddr_in addr;
			memset(&addr, 0, sizeof(addr));
			addr.sin_family      = AF_INET;
			addr.sin_addr.s_addr = inet_addr(config->ip); 
			addr.sin_port        = htons(config->port);

			if(bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) { 
				error("unable to bind");
			}

			if(listen(sock, 5) != 0) { 
				error("unable to listen");
			}

			console_log("server started on [%s:%i]", config->ip, config->port);

			if(!tun_setip(tun, inet_addr(config->gateway), inet_addr(config->subnet), CHIPVPN_MAX_MTU)) {
				error("unable to assign ip to tunnel adapter");
			}
			if(!tun_bringup(tun)) {
				error("unable to bring up tunnel adapter");
			}
		} else {
			struct sockaddr_in     addr;
			memset(&addr, 0, sizeof(addr));
			addr.sin_family      = AF_INET;
			addr.sin_addr.s_addr = inet_addr(config->ip); 
			addr.sin_port        = htons(config->port);

			console_log("connecting to [%s:%i]", config->ip, config->port);

			int connect_start = chipvpn_get_time();
			while(true) {
				if(connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != -1) {
					break;
				}
				if(chipvpn_get_time() - connect_start > 5) {
					console_log("unable to connect, reconnecting");
					goto chipvpn_cleanup;
				}
			}
			
			console_log("connected");

			VPNPeer *peer = chipvpn_peer_new(sock);
			list_insert(list_end(&peers), peer);

			console_log("key exchange begin");

			char key[32];
			chipvpn_generate_random(key, sizeof(key));

			VPNKeyPacket p_key;
			memcpy(p_key.key, key, sizeof(key));	
			chipvpn_peer_send(peer, VPN_SET_KEY, &p_key, sizeof(p_key));

			chipvpn_set_key(peer, key);

			sock = -1; // discard sock as it is replaced by the allocation of peer
		}

		int chipvpn_last_update = 0;
		struct timeval tv;

		fd_set rdset, wdset;

		while(quit == false) {
			tv.tv_sec = 0;
			tv.tv_usec = 200000;

			int max = MAX(tun->fd, sock);

			FD_ZERO(&rdset);
			FD_ZERO(&wdset);

			if(config->mode == MODE_SERVER) {
				// listening socket for server accept
				FD_SET(sock, &rdset);
			}
			FD_SET(tun->fd, &rdset);


			for(ListNode *i = list_begin(&peers); i != list_end(&peers); i = list_next(i)) {
				VPNPeer *peer = (VPNPeer*)i;
				if(!chipvpn_peer_readable(peer)) {
					/* 
						when peer's buffer cannot read fully constructed packet yet
						(attempt to read to buffer from socket)
					*/
					FD_SET(peer->fd, &rdset);
				}
				if(!chipvpn_peer_writeable(peer)) {
					/* 
						when peer's buffer cannot write fully constructed packet yet
						(attempt to flush buffer to socket)
					*/
					FD_SET(peer->fd, &wdset);
				}
				if(peer->fd > max) {
					max = peer->fd;
				}
			}

			if(select(max + 1, &rdset, &wdset, NULL, &tv) >= 0) {
				/* 
					ChipVPN's service
				*/
				if(chipvpn_get_time() - chipvpn_last_update >= 1) {
					ListNode *i = list_begin(&peers);
					while(i != list_end(&peers)) {
						VPNPeer *peer = (VPNPeer*)i;
						i = list_next(i);
						if(chipvpn_get_time() - peer->last_ping < 10) {
							if(peer->is_authed == true) {
								chipvpn_peer_send(peer, VPN_PING, NULL, 0);
								gettimeofday(&ping_start, NULL);
							}
						} else {
							chipvpn_disconnect_peer(config, peer);
						}
					}

					chipvpn_last_update = chipvpn_get_time();
				}

				/* 
					Triggered when someone connects
				*/
				if(config->mode == MODE_SERVER && FD_ISSET(sock, &rdset)) {
					// server accept
					// TODO: limit connections
					struct sockaddr_in addr;

					int fd = accept(sock, (struct sockaddr*)&addr, &(socklen_t){sizeof(addr)});
					if(fd >= 0) {
						if(chipvpn_set_socket_non_block(fd) < 0) {
							error("unable to set socket to non blocking mode");
						}

						console_log("IP: %s", inet_ntoa(addr.sin_addr));

						VPNPeer *peer = chipvpn_peer_new(fd);
						list_insert(list_end(&peers), peer);
					}
				}

				/* 
					Triggered when the peer is readable/writable
				*/
				ListNode *i = list_begin(&peers);
				while(i != list_end(&peers)) {
					VPNPeer *peer = (VPNPeer*)i;
					i = list_next(i);
					// peer is readable
					if(FD_ISSET(peer->fd, &rdset)) {
						VPNPacket packet;
						// read packet until it is a complete datagram
						int r = chipvpn_peer_dispatch_inbound(peer);
						if(r <= 0 && r != VPN_EAGAIN) {
							// peer I/O error
							chipvpn_disconnect_peer(config, peer);
							continue; // peer removed from list so skip the loop
						}

						if(chipvpn_peer_recv(peer, &packet) > 0) {
							// datagram ready
							chipvpn_socket_event(config, peer, &packet);
						}
					}

					// peer is writable
					if(FD_ISSET(peer->fd, &wdset)) {
						int w = chipvpn_peer_dispatch_outbound(peer);
						if(w <= 0 && w != VPN_EAGAIN) {
							// peer I/O error
							chipvpn_disconnect_peer(config, peer);
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
						chipvpn_tun_event(config, (VPNDataPacket*)&packet, r);
					}
				}
			}
		}

		chipvpn_cleanup:;

		ListNode *i = list_begin(&peers);
		while(i != list_end(&peers)) {
			VPNPeer *peer = (VPNPeer*)i;
			i = list_next(i);
			chipvpn_disconnect_peer(config, peer);
		}

		close(sock);
		free_tun(tun);

		if(retry == true) {
			sleep(2);
		} else {
			break;
		}
	}
}

void chipvpn_socket_event(ChipVPNConfig *config, VPNPeer *peer, VPNPacket *packet) {
	VPNPacketType type = (VPNPacketType)(packet->header.type);
	VPNPacketBody data = packet->data;

	switch(type) {
		case VPN_SET_KEY: {
			chipvpn_set_key_event(config, peer, &data.key_packet);
		}
		break;
		case VPN_TYPE_AUTH: {
			chipvpn_auth_event(config, peer, &data.auth_packet);
		}
		break;
		case VPN_TYPE_ASSIGN: {
			chipvpn_assign_event(config, peer, &data.dhcp_packet);
		}
		break;
		case VPN_TYPE_DATA: {
			chipvpn_data_event(config, peer, &data.data_packet, PLEN(packet));
		}
		break;
		case VPN_PING: {
			chipvpn_ping_event(config, peer);
		}
		break;
		case VPN_PONG: {
			chipvpn_pong_event(config, peer);
		}
		break;
		case VPN_TYPE_MSG: {

		}
		break;
		default: {
			chipvpn_disconnect_peer(config, peer);
			return;
		}
		break;
	}	
}

void chipvpn_set_key_event(ChipVPNConfig *config, VPNPeer *peer, VPNKeyPacket *packet) {
	if(config->mode == MODE_SERVER) {
		chipvpn_set_key(peer, packet->key);

		chipvpn_peer_send(peer, VPN_SET_KEY, NULL, 0);
	} else {
		console_log("key exchange success");

		VPNAuthPacket auth;
		strcpy(auth.data, config->token);
		chipvpn_peer_send(peer, VPN_TYPE_AUTH, &auth, sizeof(auth));
	}
}

void chipvpn_auth_event(ChipVPNConfig *config, VPNPeer *peer, VPNAuthPacket *packet) {
	if(config->mode == MODE_SERVER) {
		if(memcmp(packet, config->token, strlen(config->token)) == 0) {
			peer->is_authed = true;
			chipvpn_peer_send(peer, VPN_TYPE_AUTH, NULL, 0);
		} else {
			chipvpn_disconnect_peer(config, peer);
			return;
		}
	} else {
		console_log("peer authenticated");
		peer->is_authed = true;
		chipvpn_peer_send(peer, VPN_TYPE_ASSIGN, NULL, 0);
	}
}

void chipvpn_assign_event(ChipVPNConfig *config, VPNPeer *peer, VPNAssignPacket *packet) {
	if(config->mode == MODE_SERVER) {
		uint32_t alloc_ip = chipvpn_get_peer_free_ip(&peers, config->gateway);
		if(alloc_ip > 0) {
			VPNAssignPacket assign;
			assign.ip      = alloc_ip;
			assign.subnet  = inet_addr(config->subnet);
			assign.gateway = inet_addr(config->gateway);
			assign.mtu     = htonl(CHIPVPN_MAX_MTU);

			peer->internal_ip = alloc_ip;

			VPNAssignPacket p_assign_enc;

			if(!crypto_encrypt(peer->outbound_aes, &p_assign_enc, &assign, sizeof(assign))) {
				console_log("unable to encrypt packet of peer");
				chipvpn_disconnect_peer(config, peer);
				return;
			}

			chipvpn_peer_send(peer, VPN_TYPE_ASSIGN, &p_assign_enc, sizeof(assign));
		}
	} else {
		VPNAssignPacket p_assign;

		if(!crypto_decrypt(peer->inbound_aes, &p_assign, packet, sizeof(VPNAssignPacket))) {
			console_log("unable to decrypt packet of peer");
			chipvpn_disconnect_peer(config, peer);
			return;
		}

		uint32_t peer_ip      = p_assign.ip;
		uint32_t peer_subnet  = p_assign.subnet;
		uint32_t peer_gateway = p_assign.gateway;
		uint32_t peer_mtu     = ntohl(p_assign.mtu);

		if(!tun_setip(tun, peer_ip, peer_subnet, peer_mtu)) {
			error("unable to assign ip to tunnel adapter");
		}
		if(!tun_bringup(tun)) {
			error("unable to bring up tunnel adapter");
		}

		console_log("assigned dhcp: ip [%i.%i.%i.%i] gateway [%i.%i.%i.%i]", (peer_ip >> 0) & 0xFF, (peer_ip >> 8) & 0xFF, (peer_ip >> 16) & 0xFF, (peer_ip >> 24) & 0xFF, (peer_gateway >> 0) & 0xFF, (peer_gateway >> 8) & 0xFF, (peer_gateway >> 16) & 0xFF, (peer_gateway >> 24) & 0xFF);

		if(config->pull_routes) {
			console_log("setting routes");
			uint32_t default_gateway = get_default_gateway();
			if(exec_sprintf("ip route add %s via %i.%i.%i.%i", config->ip, (default_gateway >> 0) & 0xFF, (default_gateway >> 8) & 0xFF, (default_gateway >> 16) & 0xFF, (default_gateway >> 24) & 0xFF)) { }
			if(exec_sprintf("ip route add 0.0.0.0/1 via %i.%i.%i.%i", (peer_gateway >> 0) & 0xFF, (peer_gateway >> 8) & 0xFF, (peer_gateway >> 16) & 0xFF, (peer_gateway >> 24) & 0xFF)) { }
			if(exec_sprintf("ip route add 128.0.0.0/1 via %i.%i.%i.%i", (peer_gateway >> 0) & 0xFF, (peer_gateway >> 8) & 0xFF, (peer_gateway >> 16) & 0xFF, (peer_gateway >> 24) & 0xFF)) { }
		}

		peer->internal_ip = peer_ip;
		peer->tx          = 0;
		peer->rx          = 0;
		console_log("initialization sequence complete");

	}
}

void chipvpn_data_event(ChipVPNConfig *config, VPNPeer *peer, VPNDataPacket *packet, int size) {
	VPNDataPacket p_data;
	if(!crypto_decrypt(peer->inbound_aes, &p_data, packet, size)) {
		console_log("unable to decrypt packet of peer");
		chipvpn_disconnect_peer(config, peer);
		return;
	}
	
	IPPacket *ip_hdr = (IPPacket*)(&p_data.data);
	if(
		(peer->is_authed == true) &&
		((ip_hdr->dst_addr == peer->internal_ip && config->mode == MODE_CLIENT) || 
		(ip_hdr->src_addr == peer->internal_ip && config->mode == MODE_SERVER)) && 
		(size > 0 && size <= CHIPVPN_MAX_MTU)
	) {
		peer->rx += size;
		if(write(tun->fd, (char*)&p_data, size)) {}
	}
}

void chipvpn_ping_event(ChipVPNConfig *config, VPNPeer *peer) {
	peer->last_ping = chipvpn_get_time();
	chipvpn_peer_send(peer, VPN_PONG, NULL, 0);
}

void chipvpn_pong_event(ChipVPNConfig *config, VPNPeer *peer) {
	gettimeofday(&ping_stop, NULL);

	char tx[50];
	char rx[50];
	strcpy(tx, chipvpn_format_bytes(peer->tx));
	strcpy(rx, chipvpn_format_bytes(peer->rx));

	uint32_t peer_index = 0;
	for(ListNode *i = list_begin(&peers); i != list_end(&peers); i = list_next(i)) {
		if(peer == (VPNPeer*)i) {
			break;
		}
		++peer_index;
	}

	console_log("peer 0x%04x ping took %lu ms TX: %s RX: %s", peer_index, ((ping_stop.tv_sec - ping_start.tv_sec) * 1000000 + ping_stop.tv_usec - ping_start.tv_usec) / 1000, tx, rx); 
}

void chipvpn_tun_event(ChipVPNConfig *config, VPNDataPacket *packet, int size) {
	IPPacket *ip_hdr = (IPPacket*)(packet->data);

	VPNPeer *peer = chipvpn_get_peer_by_ip(&peers, config->mode == MODE_SERVER ? ip_hdr->dst_addr : ip_hdr->src_addr);
	if(
		peer && 
		peer->is_authed == true &&
		chipvpn_peer_writeable(peer)
	) {
		peer->tx += size;

		VPNDataPacket packet_enc;

		if(!crypto_encrypt(peer->outbound_aes, &packet_enc, packet, size)) {
			console_log("unable to encrypt packet of peer");
			chipvpn_disconnect_peer(config, peer);
			return;
		}

		chipvpn_peer_send(peer, VPN_TYPE_DATA, &packet_enc, size);
	}
}

void chipvpn_disconnect_peer(ChipVPNConfig *config, VPNPeer *peer) {
	console_log("peer disconnected");
	list_remove(&peer->node);
	close(peer->fd);
	chipvpn_peer_free(peer);
	if(config->mode == MODE_CLIENT) {
		console_log("disconnected, reconnecting");
		quit = true;
	}
}

void chipvpn_exit(int type) {
	if(type == 0) {}
	quit = true;
	
}


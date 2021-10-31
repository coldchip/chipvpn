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

bool quit = false;
bool retry = false;

Tun *tun = NULL;

List peers;

struct timeval ping_stop, ping_start;

void chipvpn_event_loop(ChipVPNConfig *config, void (*status)(ChipVPNStatus)) {
	while(1) {
		retry = false;
		quit = false;

		status(STATUS_CONNECTING);

		list_clear(&peers);

		tun = open_tun("");
		if(tun  == NULL) {
			error("tuntap adaptor creation failed, please run as sudo");
		}

		int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

		if(sock < 0) {
			error("unable to create socket");
		}

		signal(SIGPIPE, SIG_IGN);

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
			retry = true;
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
					retry = true;
					goto chipvpn_cleanup;
				}
			}
			
			console_log("connected");

			VPNPeer *peer = chipvpn_peer_alloc(sock);
			list_insert(list_end(&peers), peer);

			console_log("key exchange begin");

			char key[32];
			chipvpn_generate_random(key, sizeof(key));

			VPNKeyPacket p_key;
			memcpy(p_key.key, key, sizeof(key));
			chipvpn_peer_send_nio(peer, VPN_SET_KEY, &p_key, sizeof(p_key));

			chipvpn_set_key(peer, key);

			sock = -1; // discard sock as it is replaced by the allocation of peer
		}

		int chipvpn_last_update = 0;
		struct timeval tv;

		fd_set rdset;
		fd_set wdset;

		signal(SIGINT, chipvpn_event_cleanup); // let event loop handle SIGINT

		while(quit == false) {
			tv.tv_sec = 0;
			tv.tv_usec = 200000;

			int max = MAX(tun->fd, sock);

			FD_ZERO(&rdset);
			FD_ZERO(&wdset);
			if(config->mode == MODE_SERVER) {
				// main listening socket for server accept
				FD_SET(sock, &rdset);
			}
			FD_SET(tun->fd, &rdset);


			for(ListNode *i = list_begin(&peers); i != list_end(&peers); i = list_next(i)) {
				VPNPeer *peer = (VPNPeer*)i;
				FD_SET(peer->fd, &rdset);
				if(peer->outbound_buffer_pos > 0) {
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
				if(chipvpn_get_time() - chipvpn_last_update >= 2) {
					ListNode *i = list_begin(&peers);
					while(i != list_end(&peers)) {
						VPNPeer *peer = (VPNPeer*)i;
						i = list_next(i);
						if(chipvpn_get_time() - peer->last_ping < 10) {
							if(peer->is_authed == true) {
								chipvpn_peer_send_nio(peer, VPN_PING, NULL, 0);
								gettimeofday(&ping_start, NULL);
							}
						} else {
							chipvpn_peer_dealloc(peer);
							if(config->mode == MODE_CLIENT) {
								console_log("disconnected, reconnecting");
								retry = true;
								goto chipvpn_cleanup;
							}
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
					socklen_t addr_size = sizeof(addr);

					int fd = accept(sock, (struct sockaddr*)&addr, &addr_size);
					if(fd >= 0) {
						if(chipvpn_set_socket_non_block(fd) < 0) {
							error("unable to set socket to non blocking mode");
						}

						console_log("IP: %s", inet_ntoa(addr.sin_addr));

						VPNPeer *peer = chipvpn_peer_alloc(fd);
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
							chipvpn_peer_dealloc(peer);
							if(config->mode == MODE_CLIENT) {
								console_log("disconnected, reconnecting");
								retry = true;
								goto chipvpn_cleanup;
							}
							continue; // peer removed from list so skip the loop
						}

						if(chipvpn_peer_recv_nio(peer, &packet) > 0) {
							// datagram ready
							chipvpn_socket_event(config, peer, &packet, status);
						}
					}

					// peer is writable
					if(FD_ISSET(peer->fd, &wdset)) {
						int w = chipvpn_peer_dispatch_outbound(peer);
						if(w <= 0 && w != VPN_EAGAIN) {
							// peer I/O error
							chipvpn_peer_dealloc(peer);
							if(config->mode == MODE_CLIENT) {
								console_log("disconnected, reconnecting");
								retry = true;
								goto chipvpn_cleanup;
							}
							continue; // peer removed from list so skip the loop
						}
					}
				}

				/* 
					Triggered when the tunnel is readable
				*/
				if(FD_ISSET(tun->fd, &rdset)) {
					VPNDataPacket packet;
					int n = read(tun->fd, (char*)&packet, sizeof(packet));
					if(n > 0) {
						chipvpn_tun_event(config, (VPNDataPacket*)&packet, n, status);
					}
				}
			}
		}

		chipvpn_cleanup:;

		ListNode *i = list_begin(&peers);
		while(i != list_end(&peers)) {
			VPNPeer *peer = (VPNPeer*)i;
			i = list_next(i);
			chipvpn_peer_dealloc(peer);
		}

		close(sock);
		free_tun(tun);

		signal(SIGINT, SIG_DFL);

		if(status) {
			status(STATUS_DISCONNECTED);
		}

		if(retry == false) {
			break;
		}
		sleep(1);
	}
}

void chipvpn_socket_event(ChipVPNConfig *config, VPNPeer *peer, VPNPacket *packet, void (*status)(ChipVPNStatus)) {
	VPNPacketType type = (VPNPacketType)(packet->header.type);
	VPNPacketBody data = packet->data;

	switch(type) {
		case VPN_SET_KEY: {
			if(config->mode == MODE_SERVER) {
				VPNKeyPacket *p_key = &data.key_packet;
				chipvpn_set_key(peer, p_key->key);

				chipvpn_peer_send_nio(peer, VPN_SET_KEY, NULL, 0);
			} else {
				console_log("key exchange success");

				VPNAuthPacket auth;
				strcpy(auth.data, config->token);
				chipvpn_peer_send_nio(peer, VPN_TYPE_AUTH, &auth, sizeof(auth));
			}
		}
		break;
		case VPN_TYPE_AUTH: {
			if(config->mode == MODE_SERVER) {
				VPNAuthPacket *p_auth = &data.auth_packet;
				if(memcmp(p_auth, config->token, strlen(config->token)) == 0) {
					peer->is_authed = true;

					VPNDataPacket packet2;
					strcpy(packet2.data, "successfully logged in");
					chipvpn_peer_send_nio(peer, VPN_TYPE_MSG, &packet2, strlen(packet2.data) + 1);
					chipvpn_peer_send_nio(peer, VPN_TYPE_AUTH, NULL, 0);
				} else {
					VPNDataPacket packet;
					strcpy(packet.data, "unable to authenticate");
					chipvpn_peer_send_nio(peer, VPN_TYPE_MSG, &packet, strlen(packet.data) + 1);
					chipvpn_peer_dealloc(peer);
				}
			} else {
				console_log("peer authenticated");
				peer->is_authed = true;
				chipvpn_peer_send_nio(peer, VPN_TYPE_ASSIGN, NULL, 0);
			}
		}
		break;
		case VPN_TYPE_ASSIGN: {
			if(config->mode == MODE_SERVER) {
				uint32_t alloc_ip = chipvpn_get_peer_free_ip(&peers, config->gateway);
				if(alloc_ip > 0) {
					VPNAssignPacket assign;
					assign.ip      = alloc_ip;
					assign.subnet  = inet_addr(config->subnet);
					assign.gateway = inet_addr(config->gateway);
					assign.mtu     = htonl(CHIPVPN_MAX_MTU);

					peer->internal_ip = alloc_ip;

					chipvpn_peer_send_nio(peer, VPN_TYPE_ASSIGN, &assign, sizeof(assign));
				}
			} else {
				VPNAssignPacket *p_assign = &data.dhcp_packet;

				uint32_t peer_ip      = p_assign->ip;
				uint32_t peer_subnet  = p_assign->subnet;
				uint32_t peer_gateway = p_assign->gateway;
				uint32_t peer_mtu     = ntohl(p_assign->mtu);

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

				if(status) {
					status(STATUS_CONNECTED);
				}
			}
		}
		break;
		case VPN_TYPE_DATA: {
			VPNDataPacket *p_data = &data.data_packet;
			IPPacket *ip_hdr = (IPPacket*)(p_data->data);
			if(
				(peer->is_authed == true) &&
				((ip_hdr->dst_addr == peer->internal_ip && config->mode == MODE_CLIENT) || 
				(ip_hdr->src_addr == peer->internal_ip && config->mode == MODE_SERVER)) && 
				(PLEN(packet) > 0 && PLEN(packet) <= (CHIPVPN_MAX_MTU))
			) {
				peer->rx += PLEN(packet);
				if(write(tun->fd, (char*)p_data, PLEN(packet))) {}
			}
		}
		break;
		case VPN_PING: {
			peer->last_ping = chipvpn_get_time();
			chipvpn_peer_send_nio(peer, VPN_PONG, NULL, 0);
		}
		break;
		case VPN_PONG: {
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
		break;
		case VPN_TYPE_MSG: {
			if(config->mode == MODE_CLIENT) {
				VPNDataPacket *p_msg = (VPNDataPacket*)&data.data_packet;
				p_msg->data[sizeof(VPNDataPacket) - 1] = '\0';
				console_log("server => %s", p_msg->data);
			}
		}
		break;
		default: {
			chipvpn_peer_dealloc(peer);
		}
		break;
	}	
}

void chipvpn_tun_event(ChipVPNConfig *config, VPNDataPacket *packet, int size, void (*status) (ChipVPNStatus)) {
	IPPacket *ip_hdr = (IPPacket*)(packet->data);

	VPNPeer *peer = chipvpn_get_peer_by_ip(&peers, config->mode == MODE_SERVER ? ip_hdr->dst_addr : ip_hdr->src_addr);
	if(peer) {
		if(peer->is_authed == true) {
			peer->tx += size;
			chipvpn_peer_send_nio(peer, VPN_TYPE_DATA, packet, size);
		}
	}
}

void chipvpn_event_cleanup(int type) {
	if(type == 0) {}
	console_log("SIGINT received, terminating ChipVPN");
	quit = true;
}


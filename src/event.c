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

ChipVPNConfig *config = NULL;

int        ipc  = 0;
VPNSocket *host = NULL;
VPNTun    *tun  = NULL;

void chipvpn_init(ChipVPNConfig *c) {
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

	ipc = socket(AF_UNIX, SOCK_STREAM, 0);
	if(ipc < 0) {
		error("IPC socket creation failed");
	}

	tun = chipvpn_tun_open("");
	if(tun == NULL) {
		error("tuntap adapter creation failed, please run as sudo");
	}

	host = chipvpn_socket_create();
	if(host < 0) {
		error("unable to create socket");
	}

	struct sockaddr_un ipc_addr;
	ipc_addr.sun_family = AF_UNIX;        
	strcpy(ipc_addr.sun_path, "/home/ryan/chipvpn-proxy/chipvpn-auth.sock"); 

	while(true) {
		int success = connect(ipc, (struct sockaddr *)&ipc_addr, sizeof(ipc_addr));
		if(success != -1) {
			break;
		}
		console_log("unable to connect to unix socket, reconnecting");
		sleep(1);
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
		
		VPNKeyPacket packet;
		RAND_priv_bytes((unsigned char*)&packet.key, sizeof(packet.key));
		chipvpn_peer_set_key(peer, packet.key);
		console_log("key exchange success");
		if(!chipvpn_peer_send(peer, VPN_TYPE_SET_KEY, &packet, sizeof(packet))) {
			chipvpn_peer_disconnect(peer);
			return;
		}

		VPNAuthPacket auth;
		strcpy((char*)auth.token, config->token);

		if(!chipvpn_peer_send(peer, VPN_TYPE_AUTH, &auth, sizeof(auth))) {
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

		FD_SET(ipc, &rdset);
		FD_SET(tun->fd, &rdset);
		
		int max = 0;
		max = MAX(max, ipc);
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
				ChipVPN's ticker
			*/
			if(chipvpn_get_time() - chipvpn_last_update >= 2) {
				chipvpn_ticker();
				chipvpn_last_update = chipvpn_get_time();
			}

			/* 
				Triggered when IPC has data
			*/
			if(FD_ISSET(ipc, &rdset)) {
				printf("IPC has data\n");
				char buf[8192];
				int r = read(ipc, buf, sizeof(buf));
				if(r > 0) {
					chipvpn_ipc_event(buf);
				}
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
					if(chipvpn_peer_recv(peer, &packet)) {
						if(chipvpn_socket_event(peer, &packet) == VPN_CONNECTION_END) {
							// event disconnection
							chipvpn_peer_disconnect(peer);
							continue; // peer removed from list so skip the loop
						}
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
				int r = read(tun->fd, packet.data, sizeof(packet));
				if(r > 0) {
					IPPacket *ip_hdr = (IPPacket*)(packet.data);
					VPNPeer *peer = chipvpn_peer_get_by_ip(&host->peers, config->mode == MODE_SERVER ? ip_hdr->dst_addr : ip_hdr->src_addr);
					if(peer) {
						IPPacket *ip_hdr = (IPPacket*)(&packet.data);
						if(
							(chipvpn_peer_is_authed(peer)) &&
							(chipvpn_firewall_match_rule(&peer->outbound_firewall, ip_hdr->dst_addr.s_addr))
						) {
							if(peer->tx >= peer->tx_max) {
								msg_log(VPN_MSG_QUOTA_EXCEEDED);
								chipvpn_peer_send(peer, VPN_MSG_QUOTA_EXCEEDED, NULL, 0);
								chipvpn_peer_disconnect(peer);
							}

							peer->tx += r;

							if(!chipvpn_peer_send(peer, VPN_TYPE_DATA, &packet, r)) {
								chipvpn_peer_disconnect(peer);
							}
						}
					}
				}
			}
		}
	}
}

void chipvpn_cleanup() {
	close(ipc);
	if(host) {
		chipvpn_socket_free(host);
		host = NULL;
	}
	if(tun) {
		chipvpn_tun_free(tun);
		tun = NULL;
	}
}

void chipvpn_ticker() {
	if(list_size(&host->peers) == 0 && config->mode == MODE_CLIENT) {
		console_log("reconnecting...");
		terminate = true;
	}

	ListNode *i = list_begin(&host->peers);
	while(i != list_end(&host->peers)) {
		VPNPeer *peer = (VPNPeer*)i;
		i = list_next(i);
		if(chipvpn_get_time() - peer->last_ping < 20) {
			if(chipvpn_peer_is_authed(peer)) {
				if(!chipvpn_peer_send(peer, VPN_TYPE_PING, NULL, 0)) {
					chipvpn_peer_disconnect(peer);
				}
			}
		} else {
			msg_log(VPN_MSG_PEER_TIMEOUT);
			chipvpn_peer_send(peer, VPN_MSG_PEER_TIMEOUT, NULL, 0);
			chipvpn_peer_disconnect(peer);
		}
	}


}

void chipvpn_ipc_event(char *buf) {
	cJSON *json = cJSON_Parse(buf);
	if(json) {
		cJSON *cjson_type    = cJSON_GetObjectItem(json, "type");
		cJSON *cjson_success = cJSON_GetObjectItem(json, "success");
		cJSON *cjson_peerid  = cJSON_GetObjectItem(json, "peerid");

		VPNPeer *peer = NULL;
		if(cjson_peerid && cJSON_IsNumber(cjson_peerid)) {
			int peerid = cjson_peerid->valueint;

			for(ListNode *i = list_begin(&host->peers); i != list_end(&host->peers); i = list_next(i)) {
				peer = (VPNPeer*)i;
				if(peer->id == peerid) {
					break;
				}
			}
		}

		if(cjson_type && cJSON_IsString(cjson_type)) {
			char *type = cjson_type->valuestring;
			if(strcmp(type, "login") == 0) {
				if(peer && cjson_success && cJSON_IsBool(cjson_success)) {
					chipvpn_ipc_login(peer);
				}
			}
		}
		cJSON_Delete(json);
	}
}

VPNPacketError chipvpn_ipc_login(VPNPeer *peer) {
	msg_log(VPN_MSG_AUTH_SUCCESS);
	chipvpn_peer_login(peer);

	if(!chipvpn_peer_send(peer, VPN_MSG_AUTH_SUCCESS, NULL, 0)) {
		return VPN_CONNECTION_END;
	}

	if(!chipvpn_peer_send(peer, VPN_TYPE_AUTH_REPLY, NULL, 0)) {
		return VPN_CONNECTION_END;
	}

	struct in_addr gateway;
	inet_aton(config->gateway, &gateway);

	if(!chipvpn_peer_get_free_ip(&host->peers, gateway, &peer->internal_ip)) {
		msg_log(VPN_MSG_ASSIGN_EXHAUSTED);
		chipvpn_peer_send(peer, VPN_MSG_ASSIGN_EXHAUSTED, NULL, 0);
		return VPN_CONNECTION_END;
	}

	VPNAssignPacket assign = {
		.ip = peer->internal_ip.s_addr,
		.subnet = inet_addr(config->subnet),
		.gateway = inet_addr(config->gateway)
	};

	if(!chipvpn_peer_send(peer, VPN_TYPE_ASSIGN, &assign, sizeof(assign))) {
		return VPN_CONNECTION_END;
	}

	return VPN_HAS_DATA;
}

VPNPacketError chipvpn_socket_event(VPNPeer *peer, VPNPacket *packet) {
	VPNPacketType type = (VPNPacketType)(packet->header.type);
	VPNPacketBody data = packet->data;

	if(
		((type == VPN_TYPE_ASSIGN) || 
		(type == VPN_TYPE_DATA) || 
		(type == VPN_TYPE_PING)) && 
		(!chipvpn_peer_is_authed(peer))
	) {
		// zones that require authentication
		msg_log(VPN_MSG_UNAUTHORIZED);
		chipvpn_peer_send(peer, VPN_MSG_UNAUTHORIZED, NULL, 0);
		return VPN_CONNECTION_END;
	}

	if(
		((type == VPN_TYPE_SET_KEY)    && 
		(config->mode != MODE_SERVER)) || 
		((type == VPN_TYPE_AUTH)       && 
		(config->mode != MODE_SERVER)) ||
		((type == VPN_TYPE_AUTH_REPLY) && 
		(config->mode != MODE_CLIENT)) ||
		((type == VPN_TYPE_ASSIGN)     && 
		(config->mode != MODE_CLIENT))
	) {
		// mode specific zones
		msg_log(VPN_MSG_UNAUTHORIZED);
		chipvpn_peer_send(peer, VPN_MSG_UNAUTHORIZED, NULL, 0);
		return VPN_CONNECTION_END;
	}

	VPNPacketBody d_data;

	if(
		(type == VPN_TYPE_AUTH) || 
		(type == VPN_TYPE_AUTH_REPLY) || 
		(type == VPN_TYPE_ASSIGN) || 
		(type == VPN_TYPE_DATA) || 
		(type == VPN_TYPE_PING) || 
		(type == VPN_TYPE_PONG)
	) {
		// zones that require decryption
		if(!crypto_decrypt(peer->outbound_aes, &d_data, &data, PLEN(packet))) {
			msg_log(VPN_MSG_ENCRYPTION_ERROR);
			chipvpn_peer_send(peer, VPN_MSG_ENCRYPTION_ERROR, NULL, 0);
			return VPN_CONNECTION_END;
		}
	}

	switch(type) {
		case VPN_TYPE_SET_KEY: {
			return chipvpn_recv_key(peer, &data.key_packet, PLEN(packet));
		}
		break;
		case VPN_TYPE_AUTH: {
			return chipvpn_recv_auth(peer, &d_data.auth_packet, PLEN(packet));
		}
		break;
		case VPN_TYPE_AUTH_REPLY: {
			return chipvpn_recv_auth_reply(peer);
		}
		break;
		case VPN_TYPE_ASSIGN: {
			return chipvpn_recv_assign(peer, &d_data.dhcp_packet, PLEN(packet));
		}
		break;
		case VPN_TYPE_DATA: {
			return chipvpn_recv_data(peer, &d_data.data_packet, PLEN(packet));
		}
		break;
		case VPN_TYPE_PING: {
			return chipvpn_recv_ping(peer);
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
		case VPN_MSG_PEER_TIMEOUT:
		case VPN_MSG_QUOTA_EXCEEDED: {
			msg_log(type);
			return VPN_HAS_DATA;
		}
		break;
		default: {
			msg_log(VPN_MSG_PACKET_UNKNOWN);
			chipvpn_peer_send(peer, VPN_MSG_PACKET_UNKNOWN, NULL, 0);
			return VPN_CONNECTION_END;
		}
		break;
	}
	return VPN_HAS_DATA;
}

VPNPacketError chipvpn_recv_key(VPNPeer *peer, VPNKeyPacket *packet, int size) {
	console_log("key exchange success");
	chipvpn_peer_set_key(peer, packet->key);
	return VPN_HAS_DATA;
}

VPNPacketError chipvpn_recv_auth(VPNPeer *peer, VPNAuthPacket *packet, int size) {
	cJSON *payload = cJSON_CreateObject();
	cJSON_AddStringToObject(payload, "type", "login");
	cJSON_AddStringToObject(payload, "token", (const char*)packet->token);
	cJSON_AddNumberToObject(payload, "peerid", peer->id);

	char *buf = cJSON_Print(payload);

	if(write(ipc, buf, strlen(buf)) < 0) {}

	free(buf);
	cJSON_Delete(payload);
	return VPN_HAS_DATA;
}

VPNPacketError chipvpn_recv_auth_reply(VPNPeer *peer) {
	chipvpn_peer_login(peer);
	return VPN_HAS_DATA;
}

VPNPacketError chipvpn_recv_assign(VPNPeer *peer, VPNAssignPacket *packet, int size) {
	struct in_addr peer_ip, peer_subnet, peer_gateway;

	peer_ip.s_addr        = packet->ip;
	peer_subnet.s_addr    = packet->subnet;
	peer_gateway.s_addr   = packet->gateway;
	uint32_t peer_mtu     = ntohl(packet->mtu);

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

		struct in_addr default_gateway;
		if(!get_default_gateway(&default_gateway)) {
			error("unable to retrieve default gateway from system");
		}

		char default_gateway_c[24];
		strcpy(default_gateway_c, inet_ntoa(default_gateway));

		if(!exec_sprintf("ip route add %s via %s", config->ip, default_gateway_c)) { }
		if(!exec_sprintf("ip route add 0.0.0.0/1 via %s", peer_gateway_c)) { }
		if(!exec_sprintf("ip route add 128.0.0.0/1 via %s", peer_gateway_c)) { }
	}

	peer->internal_ip = peer_ip;

	console_log("initialization sequence complete");
	return VPN_HAS_DATA;
}

VPNPacketError chipvpn_recv_data(VPNPeer *peer, VPNDataPacket *packet, int size) {
	IPPacket *ip_hdr = (IPPacket*)(&packet->data);
	if(
		(chipvpn_firewall_match_rule(&peer->inbound_firewall, ip_hdr->dst_addr.s_addr)) &&
		((ip_hdr->dst_addr.s_addr == peer->internal_ip.s_addr && config->mode == MODE_CLIENT) || 
		(ip_hdr->src_addr.s_addr == peer->internal_ip.s_addr && config->mode == MODE_SERVER)) && 
		(size > 0 && size <= CHIPVPN_MAX_MTU)
	) {
		if(peer->rx >= peer->rx_max) {
			msg_log(VPN_MSG_QUOTA_EXCEEDED);
			chipvpn_peer_send(peer, VPN_MSG_QUOTA_EXCEEDED, NULL, 0);
			return VPN_CONNECTION_END;
		}
		peer->rx += size;
		if(write(tun->fd, packet->data, size) != size) {
			error("unable to write to tun adapter");
		}
	}
	return VPN_HAS_DATA;
}

VPNPacketError chipvpn_recv_ping(VPNPeer *peer) {
	char tx[50];
	char rx[50];
	char tx_max[50];
	char rx_max[50];
	strcpy(tx, chipvpn_format_bytes(peer->tx));
	strcpy(rx, chipvpn_format_bytes(peer->rx));
	strcpy(tx_max, chipvpn_format_bytes(peer->tx_max));
	strcpy(rx_max, chipvpn_format_bytes(peer->rx_max));
	console_log("heartbeat from peer [%p] tx: %s/%s rx: %s/%s", peer, tx, tx_max, rx, rx_max);

	peer->last_ping = chipvpn_get_time();
	return VPN_HAS_DATA; 
}

void chipvpn_exit(int type) {
	if(type == 0) {}
	chipvpn_cleanup();
	console_log("terminating");
	exit(0);
}
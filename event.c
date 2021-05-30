#include "event.h"
#include "tun.h"
#include "chipvpn.h"
#include "peer.h"
#include "packet.h"
#include "crypto.h"
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

Tun *tun = NULL;

List peers;

struct timeval ping_stop, ping_start;

void chipvpn_event_loop(ChipVPNConfig *config) {
	chipvpn_start:;

	bool retry = false;

	console_log("ColdChip ChipVPN");

	list_clear(&peers);

	tun = open_tun("");
	if(tun  == NULL) {
		error("tuntap adaptor creation failed, please run as sudo");
	}

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock < 0) {
		error("unable to create socket");
	}

	signal(SIGPIPE, SIG_IGN);

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

	if(config->is_server) {
		struct sockaddr_in     addr;
		addr.sin_family      = AF_INET;
		addr.sin_addr.s_addr = inet_addr(config->ip); 
		addr.sin_port        = htons(config->port);

		if(bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) { 
			error("unable to bind");
		}

		if(listen(sock, 5) != 0) { 
			error("unable to listen");
		}

		console_log("server started on %s:%i", config->ip, config->port);

		if(!tun_setip(tun, inet_addr(config->gateway), inet_addr(config->subnet), MAX_MTU)) {
			error("unable to assign ip to tunnel adapter");
		}
		if(!tun_bringup(tun)) {
			error("unable to bring up tunnel adapter");
		}
	} else {
		struct sockaddr_in     addr;
		addr.sin_family      = AF_INET;
		addr.sin_addr.s_addr = inet_addr(config->ip); 
		addr.sin_port        = htons(config->port);

		console_log("connecting to [%s:%i]", config->ip, config->port);

		if(connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
			console_log("unable to connect, reconnecting");
			retry = true;
			goto chipvpn_cleanup;
		}

		console_log("connected");

		VPNPeer *peer = chipvpn_peer_alloc(sock);
		list_insert(list_end(&peers), peer);

		VPNAuthPacket auth;
		strcpy(auth.data, config->token);
		chipvpn_peer_send_packet(peer, VPN_TYPE_AUTH, &auth, sizeof(auth));
	}

	int server_last_update = 0;
	struct timeval tv;

	fd_set rdset;

	signal(SIGINT, chipvpn_event_cleanup);

	while(quit == false) {
		tv.tv_sec = 0;
    	tv.tv_usec = 200000;

		FD_ZERO(&rdset);
		FD_SET(sock, &rdset);
		FD_SET(tun->fd, &rdset);

		int max = max(tun->fd, sock);

		for(ListNode *i = list_begin(&peers); i != list_end(&peers); i = list_next(i)) {
			VPNPeer *peer = (VPNPeer*)i;
			FD_SET(peer->fd, &rdset);
			if(peer->fd > max) {
				max = peer->fd;
			}
		}

		if(select(max + 1, &rdset, NULL, NULL, &tv) >= 0) {
			if(chipvpn_get_time() - server_last_update >= 2) {
				ListNode *i = list_begin(&peers);
				while(i != list_end(&peers)) {
					VPNPeer *peer = (VPNPeer*)i;
					i = list_next(i);
					if(chipvpn_get_time() - peer->last_ping < 10) {
						chipvpn_peer_send_packet(peer, VPN_PING, NULL, 0);
						gettimeofday(&ping_start, NULL);
					} else {
						chipvpn_peer_dealloc(peer);
						if(!config->is_server) {
							console_log("disconnected, reconnecting");
							retry = true;
							goto chipvpn_cleanup;
						}
					}
				}
				server_last_update = chipvpn_get_time();
			}

			if(config->is_server == true) {
				if(FD_ISSET(sock, &rdset)) {
					struct sockaddr_in addr;
					socklen_t len = sizeof(addr);
					int fd = accept(sock, (struct sockaddr*)&addr, &len);

					VPNPeer *peer = chipvpn_peer_alloc(fd);
					list_insert(list_end(&peers), peer);
				}
			}

			ListNode *i = list_begin(&peers);
			while(i != list_end(&peers)) {
				VPNPeer *peer = (VPNPeer*)i;
				i = list_next(i);
				if(FD_ISSET(peer->fd, &rdset)) {
					VPNPacket packet;
					int n = chipvpn_peer_recv_packet(peer, &packet);
					if(n > 0) {
						chipvpn_socket_event(config, peer, &packet);
					} else if(n < 0) {
						chipvpn_peer_dealloc(peer);
						if(!config->is_server) {
							console_log("disconnected, reconnecting");
							retry = true;
							goto chipvpn_cleanup;
						}
					}
				}
			}

			if(FD_ISSET(tun->fd, &rdset)) {
				VPNDataPacket packet;
				int n = read(tun->fd, (char*)&packet, sizeof(packet));
				if(n > 0) {
					chipvpn_tun_event(config, (VPNDataPacket*)&packet, n);
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

	if(retry == true) {
		sleep(1);
		goto chipvpn_start;
	}
}

void chipvpn_socket_event(ChipVPNConfig *config, VPNPeer *peer, VPNPacket *packet) {
	VPNPacketType type = ntohl(packet->header.type);
	uint32_t      size = ntohl(packet->header.size);

	switch(type) {
		case VPN_TYPE_AUTH: {
			if(config->is_server) {
				VPNAuthPacket *p_auth = &packet->data.auth_packet;
				if(memcmp(p_auth, config->token, strlen(config->token)) == 0) {
					uint32_t alloc_ip = chipvpn_get_peer_free_ip(&peers, config->gateway);
					if(alloc_ip > 0) {
						VPNAssignPacket packet;
						packet.ip      = alloc_ip;
						packet.subnet  = inet_addr(config->subnet);
						packet.gateway = inet_addr(config->gateway);
						packet.mtu     = htonl(MAX_MTU);

						chipvpn_peer_send_packet(peer, VPN_TYPE_ASSIGN, &packet, sizeof(packet));

						peer->is_authed = true;
						peer->internal_ip = alloc_ip;

						VPNDataPacket packet2;
						strcpy(packet2.data, "successfully logged in");
						chipvpn_peer_send_packet(peer, VPN_TYPE_MSG, &packet2, strlen(packet2.data) + 1);
					}
				} else {
					VPNDataPacket packet;
					strcpy(packet.data, "unable to authenticate");
					chipvpn_peer_send_packet(peer, VPN_TYPE_MSG, &packet, strlen(packet.data) + 1);
					chipvpn_peer_dealloc(peer);
				}
			}
		}
		break;
		case VPN_TYPE_ASSIGN: {
			if(!config->is_server) {
				VPNAssignPacket *p_assign = &packet->data.dhcp_packet;

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
				peer->is_authed   = true;
				peer->internal_ip = peer_ip;
				peer->tx          = 0;
				peer->rx          = 0;
				console_log("initialization sequence complete");
			}
		}
		break;
		case VPN_TYPE_DATA: {
			VPNDataPacket *p_data = (VPNDataPacket*)&packet->data.data_packet;
			IPPacket *ip_hdr = (IPPacket*)(p_data);
			if(
				peer->is_authed == true &&
				((ip_hdr->dst_addr == peer->internal_ip && !config->is_server) || 
				(ip_hdr->src_addr == peer->internal_ip && config->is_server)) && 
				(size > 0 && size <= (MAX_MTU))
			) {
				peer->rx += size;
				if(write(tun->fd, (char*)p_data, size)) {}
			}
		}
		break;
		case VPN_PING: {
			peer->last_ping = chipvpn_get_time();
			chipvpn_peer_send_packet(peer, VPN_PONG, NULL, 0);
		}
		break;
		case VPN_PONG: {
			gettimeofday(&ping_stop, NULL);
			console_log("peer %p ping took %lu ms TX: %lu RX: %lu", peer, ((ping_stop.tv_sec - ping_start.tv_sec) * 1000000 + ping_stop.tv_usec - ping_start.tv_usec) / 1000, peer->tx, peer->rx); 
		}
		break;
		case VPN_TYPE_MSG: {
			if(!config->is_server) {
				VPNDataPacket *p_msg = (VPNDataPacket*)&packet->data.data_packet;
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

void chipvpn_tun_event(ChipVPNConfig *config, VPNDataPacket *packet, int size) {
	IPPacket *ip_hdr = (IPPacket*)packet;

	VPNPeer *peer = chipvpn_get_peer_by_ip(&peers, config->is_server ? ip_hdr->dst_addr : ip_hdr->src_addr);
	if(peer) {
		if(peer->is_authed == true) {
			peer->tx += size;
			chipvpn_peer_send_packet(peer, VPN_TYPE_DATA, packet, size);
		}
	}
}

void chipvpn_event_cleanup(int type) {
	if(type == 0) {}
	console_log("SIGINT received, terminating ChipVPN");
    quit = true;
}


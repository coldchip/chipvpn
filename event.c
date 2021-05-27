#include "event.h"
#include "tun.h"
#include "chipvpn.h"
#include "peer.h"
#include "packet.h"
#include "crypto.h"
#include "list.h"
#include "json/include/cJSON.h"
#include <unistd.h>
#include <sys/types.h>
#include <stdbool.h>
#include <sys/time.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#ifdef _WIN32
	#include <winsock2.h>
	#include <windows.h>
	typedef int socklen_t;
#else
	#include <netinet/tcp.h>
	#include <netdb.h> 
	#include <sys/socket.h>
	#include <arpa/inet.h> 
	#include <netinet/in.h>
#endif

bool quit = false;
bool retry = false;

Tun *tun = NULL;

char     ip[32];
int      port                 = 0;
char     token[1024]          = "abcdef";
bool     is_server            = false;
bool     pull_routes          = false;
int      max_peers            = 8;
char     gateway[32]          = "10.9.8.1";
char     subnet[32]           = "255.255.255.0";

List peers;

struct timeval ping_stop, ping_start;

void chipvpn_load_config(char *config_file) {
	char *config = read_file_into_buffer(config_file);

	if(!config) {
		error("config %s not found", config_file);
	}

	cJSON *json = cJSON_Parse(config);
	if(!json) {
		error("Unable to parse config");
	}
	cJSON *cjson_connect         = cJSON_GetObjectItem(json, "connect");
	cJSON *cjson_bind            = cJSON_GetObjectItem(json, "bind");
	cJSON *cjson_port            = cJSON_GetObjectItem(json, "port");
	cJSON *cjson_token           = cJSON_GetObjectItem(json, "token");
	cJSON *cjson_pull_routes     = cJSON_GetObjectItem(json, "pull_routes");
	cJSON *cjson_max_peers       = cJSON_GetObjectItem(json, "max_peers");
	cJSON *cjson_gateway         = cJSON_GetObjectItem(json, "gateway");
	cJSON *cjson_subnet          = cJSON_GetObjectItem(json, "subnet");

	if(
		((cjson_connect && cJSON_IsString(cjson_connect)) || 
		(cjson_bind && cJSON_IsString(cjson_bind))) && 
		(cjson_port && cJSON_IsNumber(cjson_port)) &&
		(cjson_token && cJSON_IsString(cjson_token))
	) {
		if(cjson_connect && cJSON_IsString(cjson_connect)) {
			is_server = false;
			while(true) {
				struct hostent *he = gethostbyname(cjson_connect->valuestring);
				if(he != NULL) {
					struct in_addr *domain = ((struct in_addr **)he->h_addr_list)[0];
					if(domain != NULL) {
						strcpy(ip, inet_ntoa(*domain));
						break;
					}
				}
				warning("unable to resolve hostname, retrying");
				sleep(1);
			}
		} else {
			is_server = true;
			while(true) {
				struct hostent *he = gethostbyname(cjson_bind->valuestring);
				if(he != NULL) {
					struct in_addr *domain = ((struct in_addr **)he->h_addr_list)[0];
					if(domain != NULL) {
						strcpy(ip, inet_ntoa(*domain));
						break;
					}
				}
				warning("unable to resolve hostname, retrying");
				sleep(1);
			}
			
		}
		if(cjson_pull_routes && cJSON_IsBool(cjson_pull_routes) && cJSON_IsTrue(cjson_pull_routes)) {
			pull_routes = true;
		}
		if(cjson_max_peers && cJSON_IsNumber(cjson_max_peers) && cjson_max_peers->valueint > 0) {
			max_peers = cjson_max_peers->valueint;
		}
		if(
			(cjson_gateway && cJSON_IsString(cjson_gateway)) && 
			(cjson_subnet && cJSON_IsString(cjson_subnet))
		) {
			strcpy(gateway, cjson_gateway->valuestring);
			strcpy(subnet, cjson_subnet->valuestring);
		}

		port  = cjson_port->valueint;
		strcpy(token, cjson_token->valuestring);
	} else {
		error("incomplete config");
	}

	free(config);
	cJSON_Delete(json);
}

void chipvpn_event_loop(char *config_file) {
	chipvpn:;
	#ifdef _WIN32
		WSADATA wsa_data;
		int res = WSAStartup(MAKEWORD(2,2), &wsa_data);
		if(res != 0) {
			error("WSAStartup failed with error: %d\n", res);
		}
	#endif

	chipvpn_load_config(config_file);

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

	#ifdef _WIN32
		signal(SIGFPE, SIG_IGN);
	#else
		signal(SIGPIPE, SIG_IGN);
	#endif

	if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &(char){1}, sizeof(int)) < 0){
		error("unable to call setsockopt");
	}
	if(setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &(char){1}, sizeof(int)) < 0){
		error("unable to call setsockopt");
	}

	if(is_server) {
		struct sockaddr_in     addr;
		addr.sin_family      = AF_INET;
		addr.sin_addr.s_addr = inet_addr(ip); 
		addr.sin_port        = htons(port);

		if(bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) { 
			error("unable to bind");
		}

		if(listen(sock, 5) != 0) { 
			error("unable to listen");
		}

		console_log("server started on %s:%i", ip, port);

		if(!tun_setip(tun, inet_addr(gateway), inet_addr(subnet), MAX_MTU)) {
			error("unable to assign ip to tunnel adapter");
		}
		if(!tun_bringup(tun)) {
			error("unable to bring up tunnel adapter");
		}
	} else {
		struct sockaddr_in     addr;
		addr.sin_family      = AF_INET;
		addr.sin_addr.s_addr = inet_addr(ip); 
		addr.sin_port        = htons(port);

		console_log("connecting to %s:%i", ip, port);

		if(connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
			console_log("unable to connect, reconnecting");
			sleep(1);
			goto cleanup;
		}

		console_log("connected");

		VPNPeer *peer = chipvpn_peer_alloc(sock);
		list_insert(list_end(&peers), peer);

		VPNAuthPacket auth;
		strcpy(auth.data, token);
		chipvpn_peer_send_packet(peer, VPN_TYPE_AUTH, &auth, sizeof(auth));

	}

	int server_last_update = 0;
	struct timeval tv;

	fd_set rdset;

	#ifdef _WIN32
		if(!SetConsoleCtrlHandler(chipvpn_event_cleanup_windows, true)) {
			error("unable to register control handler");
		}
	#else
		signal(SIGINT, chipvpn_event_cleanup_unix);
	#endif

	while(quit == false) {
		tv.tv_sec = 1;
    	tv.tv_usec = 0;


		FD_ZERO(&rdset);
		FD_SET(sock, &rdset);

		#ifdef _WIN32
			int max = sock;
		#else
			FD_SET(tun->fd, &rdset);
			int max = max(tun->fd, sock);
		#endif

		for(ListNode *i = list_begin(&peers); i != list_end(&peers); i = list_next(i)) {
			VPNPeer *peer = (VPNPeer*)i;
			FD_SET(peer->fd, &rdset);
			if(peer->fd > max) {
				max = peer->fd;
			}
		}
		select(max + 1, &rdset, NULL, NULL, &tv);

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
					if(!is_server) {
						console_log("disconnected, reconnecting");
						sleep(1);
						goto cleanup;
					}
				}
			}
			server_last_update = chipvpn_get_time();
		}

		if(is_server == true) {
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
					chipvpn_socket_event(peer, &packet);
				} else if(n < 0) {
					chipvpn_peer_dealloc(peer);
					if(!is_server) {
						console_log("disconnected, reconnecting");
						sleep(1);
						goto cleanup;
					}
				}
			}
		}

		#ifndef _WIN32
			if(FD_ISSET(tun->fd, &rdset)) {
				VPNDataPacket packet;
				int n = read(tun->fd, (char*)&packet, sizeof(packet));
				if(n > 0) {
					chipvpn_tun_event((VPNDataPacket*)&packet, n);
				}
			}
		#endif
	}

	cleanup:;

	ListNode *i = list_begin(&peers);
	while(i != list_end(&peers)) {
		VPNPeer *peer = (VPNPeer*)i;
		i = list_next(i);
		chipvpn_peer_dealloc(peer);
	}

	#ifdef _WIN32
		closesocket(sock);
		WSACleanup();
	#else
		close(sock);
	#endif
	free_tun(tun);

	signal(SIGINT, SIG_DFL);

	if(retry == true) {
		quit = false;
		retry = false;
		sleep(1);
		goto chipvpn;
	}
}

void chipvpn_socket_event(VPNPeer *peer, VPNPacket *packet) {
	VPNPacketType type = ntohl(packet->header.type);
	uint32_t      size = ntohl(packet->header.size);

	switch(type) {
		case VPN_TYPE_AUTH: {
			if(is_server) {
				VPNAuthPacket *p_auth = &packet->data.auth_packet;
				if(memcmp(p_auth, token, strlen(token)) == 0) {
					uint32_t alloc_ip = chipvpn_get_peer_free_ip(&peers, gateway);
					if(alloc_ip > 0) {
						VPNAssignPacket packet;
						packet.ip      = alloc_ip;
						packet.subnet  = inet_addr(subnet);
						packet.gateway = inet_addr(gateway);
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
			if(!is_server) {
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

				if(pull_routes) {
					console_log("setting routes");
					#ifdef _WIN32
						//if(exec_sprintf("route add 0.0.0.0 mask 0.0.0.0 %s", ip)) { }
					#else
						uint32_t default_gateway = get_default_gateway();
						if(exec_sprintf("ip route add %s via %i.%i.%i.%i", ip, (default_gateway >> 0) & 0xFF, (default_gateway >> 8) & 0xFF, (default_gateway >> 16) & 0xFF, (default_gateway >> 24) & 0xFF)) { }
						if(exec_sprintf("ip route add 0.0.0.0/1 via %i.%i.%i.%i", (peer_gateway >> 0) & 0xFF, (peer_gateway >> 8) & 0xFF, (peer_gateway >> 16) & 0xFF, (peer_gateway >> 24) & 0xFF)) { }
						if(exec_sprintf("ip route add 128.0.0.0/1 via %i.%i.%i.%i", (peer_gateway >> 0) & 0xFF, (peer_gateway >> 8) & 0xFF, (peer_gateway >> 16) & 0xFF, (peer_gateway >> 24) & 0xFF)) { }
					#endif
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
				((ip_hdr->dst_addr == peer->internal_ip && !is_server) || 
				(ip_hdr->src_addr == peer->internal_ip && is_server)) && 
				(size > 0 && size <= (MAX_MTU))
			) {
				peer->rx += size;
				#ifdef _WIN32
					SendPacket(tun, p_data, size);
				#else
					if(write(tun->fd, (char*)p_data, size)) {}
				#endif
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
			if(!is_server) {
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

void chipvpn_tun_event(VPNDataPacket *packet, int size) {
	IPPacket *ip_hdr = (IPPacket*)packet;

	VPNPeer *peer = chipvpn_get_peer_by_ip(&peers, is_server ? ip_hdr->dst_addr : ip_hdr->src_addr);
	if(peer) {
		if(peer->is_authed == true) {
			peer->tx += size;
			chipvpn_peer_send_packet(peer, VPN_TYPE_DATA, packet, size);
		}
	}
}

#ifdef _WIN32

BOOL WINAPI chipvpn_event_cleanup_windows(_In_ DWORD type) {
	switch (type) {
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
	case CTRL_CLOSE_EVENT:
	case CTRL_LOGOFF_EVENT:
	case CTRL_SHUTDOWN_EVENT:
		console_log("terminating ChipVPN");
		quit = true;
		return true;
	}
	return false;
}

#else

void chipvpn_event_cleanup_unix(int type) {
	if(type == 0) {}
	console_log("terminating ChipVPN");
    quit = true;
}

#endif
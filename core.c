#include "json/include/cJSON.h"
#include "chipvpn.h"

Tun *tun = NULL;

char     ip[32];
int      port        = 0;
char    *token       = NULL;
bool     is_server   = false;
bool     pull_routes = false;
int      max_peers   = 8;

List peers;

void chipvpn_event_loop(char *config_file) {
	signal(SIGPIPE, SIG_IGN);

	list_clear(&peers);

	char *config = read_file_into_buffer(config_file);

	if(!config) {
		error("config %s not found", config_file);
	}

	cJSON *json = cJSON_Parse(config);
	if(!json) {
		error("Unable to parse config");
	}
	cJSON *cjson_connect     = cJSON_GetObjectItem(json, "connect");
	cJSON *cjson_bind        = cJSON_GetObjectItem(json, "bind");
	cJSON *cjson_port        = cJSON_GetObjectItem(json, "port");
	cJSON *cjson_token       = cJSON_GetObjectItem(json, "token");
	cJSON *cjson_pull_routes = cJSON_GetObjectItem(json, "pull_routes");
	cJSON *cjson_max_peers   = cJSON_GetObjectItem(json, "max_peers");

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
				console_log("Unable to resolve hostname, retrying");
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
				console_log("Unable to resolve hostname, retrying");
				sleep(1);
			}
			
		}
		if(cjson_pull_routes && cJSON_IsTrue(cjson_pull_routes)) {
			pull_routes = true;
		}
		if(cjson_max_peers && cJSON_IsNumber(cjson_max_peers) && cjson_max_peers->valueint > 0) {
			max_peers = cjson_max_peers->valueint;
		}
		port  = cjson_port->valueint;
		token = cjson_token->valuestring;
	} else {
		error("Incomplete config");
	}

	tun = open_tun("");
	if(tun < 0 || tun  == NULL) {
		error("Tuntap adaptor creation failed, please run as sudo");
	}

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock < 0) {
		error("unable to create socket");
	}

	if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0){
		error("unable to call setsockopt");
	}

	if(setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int)) < 0){
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

		setifip(tun, inet_addr("10.0.0.1"), inet_addr("255.255.255.0"), MAX_MTU);
		ifup(tun);
	} else {
		struct sockaddr_in     addr;
		addr.sin_family      = AF_INET;
		addr.sin_addr.s_addr = inet_addr(ip); 
		addr.sin_port        = htons(port);

		reconnect:;

		console_log("connecting to %s:%i", ip, port);

		if(connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
			console_log("unable to connect, reconnecting");
			sleep(1);
			goto reconnect;
		}

		console_log("connected");

		VPNPeer *peer = chipvpn_peer_alloc(sock);
		list_insert(list_end(&peers), peer);

		VPNAuthPacket auth;
		strcpy(auth.data, token);

		chipvpn_peer_send(peer, VPN_TYPE_AUTH, &auth, sizeof(auth));

	}

	int server_last_update = 0;
	struct timeval tv;

	fd_set rdset;

	while(1) {
		tv.tv_sec = 1;
    	tv.tv_usec = 0;

		FD_ZERO(&rdset);
		FD_SET(tun->fd, &rdset);
		FD_SET(sock, &rdset);

		int max = max(tun->fd, sock);

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
					int zero = 0;
					chipvpn_peer_send(peer, VPN_PING, &zero, sizeof(zero));
				} else {
					chipvpn_peer_dealloc(peer);
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
				VPNPacket       *packet = (VPNPacket*)&peer->buffer;
				int              size   = ntohl(packet->header.size);
				uint32_t         left   = sizeof(VPNPacketHeader) - peer->buffer_pos;

				if(peer->buffer_pos >= sizeof(VPNPacketHeader)) {
					left += size;
				}

				if((left + peer->buffer_pos) < sizeof(peer->buffer)) {
					int readed = recv(peer->fd, &peer->buffer[peer->buffer_pos], left, 0);
					if(readed > 0) {
						peer->buffer_pos += readed;
					} else {
						chipvpn_peer_dealloc(peer);
					}
				} else {
					chipvpn_peer_dealloc(peer);
				}

				if(
					peer->buffer_pos >= (size + sizeof(VPNPacketHeader))
				) {
					peer->buffer_pos = 0;
					chipvpn_socket_event(peer, packet);
				}
			}
		}

		if(FD_ISSET(tun->fd, &rdset)) {
			VPNDataPacket packet;
			int size = read(tun->fd, (char*)&packet, sizeof(packet));
			chipvpn_tun_event((VPNDataPacket*)&packet, size);
		}
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
					uint32_t alloc_ip = chipvpn_get_peer_free_ip();
					if(alloc_ip > 0) {
						VPNAssignPacket data;
						data.ip      = alloc_ip;
						data.subnet  = inet_addr("255.255.255.0");
						data.gateway = inet_addr("10.0.0.1");
						data.mtu     = htonl(MAX_MTU);
						// chip_encrypt_buf((char*)&data, sizeof(data), &vpn_peer->key);
						chipvpn_peer_send(peer, VPN_TYPE_ASSIGN, &data, sizeof(data));

						peer->is_authed = true;
						peer->internal_ip = alloc_ip;
					}
				} else {
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

				setifip(tun, peer_ip, peer_subnet, peer_mtu);
				ifup(tun);

				console_log("assigned dhcp: ip [%i.%i.%i.%i] gateway [%i.%i.%i.%i]", (peer_ip >> 0) & 0xFF, (peer_ip >> 8) & 0xFF, (peer_ip >> 16) & 0xFF, (peer_ip >> 24) & 0xFF, (peer_gateway >> 0) & 0xFF, (peer_gateway >> 8) & 0xFF, (peer_gateway >> 16) & 0xFF, (peer_gateway >> 24) & 0xFF);

				if(pull_routes) {
					console_log("setting routes");
					uint32_t default_gateway = get_default_gateway();
					if(exec_sprintf("ip route add %s via %i.%i.%i.%i", ip, (default_gateway >> 0) & 0xFF, (default_gateway >> 8) & 0xFF, (default_gateway >> 16) & 0xFF, (default_gateway >> 24) & 0xFF)) { }
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
			chip_decrypt_buf((char*)p_data, size);
			IPPacket *ip_hdr = (IPPacket*)(p_data);
			if(
				peer->is_authed == true &&
				((ip_hdr->dst_addr == peer->internal_ip && !is_server) || 
				(ip_hdr->src_addr == peer->internal_ip && is_server)) && 
				(size > 0 && size <= (MAX_MTU))
			) {
				peer->rx += size;
				if(write(tun->fd, (char*)p_data, size)) {}
			}
		}
		break;
		case VPN_PING: {
			peer->last_ping = chipvpn_get_time();
		}
		break;
		default: {

		}
		break;
	}	
}

void chipvpn_tun_event(VPNDataPacket *packet, int size) {
	IPPacket *ip_hdr = (IPPacket*)packet;

	VPNPeer *peer = chipvpn_get_peer_by_ip(is_server ? ip_hdr->dst_addr : ip_hdr->src_addr);
	if(peer) {
		if(peer->is_authed == true) {
			peer->tx += size;
			chip_encrypt_buf((char*)packet, size);
			chipvpn_peer_send(peer, VPN_TYPE_DATA, packet, size);
		}
	}
}

VPNPeer *chipvpn_peer_alloc(int fd) {
	console_log("client connected");
	VPNPeer *peer = malloc(sizeof(VPNPeer));
	peer->fd = fd;
	peer->last_ping = chipvpn_get_time();
	peer->buffer_pos = 0;
	return peer;
}

void chipvpn_peer_dealloc(VPNPeer *peer) {
	list_remove(&peer->node);
	console_log("client disconnected");
	close(peer->fd);
	free(peer);
}

void chipvpn_peer_send(VPNPeer *peer, VPNPacketType type, void *data, int size) {
	VPNPacket *packet = malloc(sizeof(VPNPacket) + size);
	packet->header.size = htonl(size);
	packet->header.type = htonl(type);
	if(data) {
		memcpy((char*)&packet->data, data, size);
	}
	send(peer->fd, (char*)packet, sizeof(packet->header) + size, 0);
	free(packet);
}

uint32_t chipvpn_get_peer_free_ip() {
	uint32_t start = inet_addr("10.0.0.100");
	uint32_t end   = inet_addr("10.0.0.200");
	bool     trip  = false;

	for(uint32_t ip = ntohl(start); ip < ntohl(end); ip++) {
		trip = false;
		for(ListNode *i = list_begin(&peers); i != list_end(&peers); i = list_next(i)) {
			VPNPeer *peer = (VPNPeer*)i;
			if(
				(peer->internal_ip == htonl(ip))
			) {
				trip = true;
			}
		}
		if(trip == false) {
			return htonl(ip);
		}
	}

	return 0;
}

VPNPeer *chipvpn_get_peer_by_ip(uint32_t ip) {
	for(ListNode *i = list_begin(&peers); i != list_end(&peers); i = list_next(i)) {
		VPNPeer *peer = (VPNPeer*)i;
		if(
			(peer->internal_ip == ip)
		) {
			return peer;
		}
	}
	return NULL;
}

uint32_t chipvpn_get_time() {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000 + tv.tv_usec / 1000) / 1000;
}
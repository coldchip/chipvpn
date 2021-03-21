#include "json/include/cJSON.h"
#include "chipvpn.h"

void chipvpn_event_loop(char *config_file) {
	char *ip          = NULL;
	int   port        = 0;
	char *token       = NULL;
	bool  is_server   = false;
	bool  pull_routes = false;
	int   max_peers   = 8;

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
			ip = cjson_connect->valuestring;
		} else {
			is_server = true;
			ip = cjson_bind->valuestring;
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

	Tun *tun = open_tun("");
	if(tun < 0 || tun  == NULL) {
		error("Tuntap adaptor creation failed, please run as sudo");
	}

	Socket *socket = chip_host_create(is_server ? max_peers : 1);
	if(!socket) {
		error("Unable to create socket");
	}

	if(!is_server) {
		Peer *peer = chip_host_connect(socket, ip, port);
		if(!peer) {
			error("Unable to init connection with server");
		}
	} else {
		if(!chip_host_bind(socket, ip, port)) {
			error("Bind failed");
		}
		setifip(tun, inet_addr("10.0.0.1"), inet_addr("255.255.255.0"), MAX_MTU);
		ifup(tun);
	}

	chip_host_select(socket, tun->fd);

	SocketEvent event;

	while(1) {
		if((chip_host_event(socket, &event) > 0)) {
			switch(event.type) {
				case EVENT_CONNECT: {
					
					console_log("Connected");

					// Allocate VPN Client
					VPNPeer *vpn_peer = malloc(sizeof(VPNPeer));
					vpn_peer->enc_ctx = chip_encrypt_init();

					// Bind VPN Client to socket
					Peer *peer = event.peer;
					peer->data = (void*)vpn_peer;

					if(!is_server) {
						console_log("Authenticating");
						char data[strlen(token) + sizeof(int)];
						*(int*)(((char*)&data) + 0) = htonl(VPN_TYPE_AUTH);
						memcpy((((char*)&data) + 4), token, strlen(token));
						chip_peer_send(peer, data, sizeof(data), RELIABLE);
					}
					
				}
				break;

				case EVENT_RECEIVE: {
					int  p_type = ntohl(*(int*)event.data);
					char *p_data = ((char*)event.data) + 4;
					int size = event.size - 4;

					Peer *peer = event.peer;
					VPNPeer *vpn_peer = ((VPNPeer*)(peer->data));

					switch(p_type) {
						case VPN_TYPE_AUTH: {
							if(is_server) {
								if(size == strlen(token) && memcmp(p_data, token, strlen(token)) == 0) {
									uint32_t alloc_ip = chipvpn_get_peer_free_ip(socket);
									if(alloc_ip > 0) {
										char data[36];
										vpn_peer->internal_ip = alloc_ip;

										char key[16];
										chipvpn_fill_pseudo_random(key, sizeof(key));
										chip_encrypt_set_key(vpn_peer->enc_ctx, key);

										*(int*)(((char*)&data) + 0)  = htonl(VPN_TYPE_ASSIGN);
										*(int*)(((char*)&data) + 4)  = alloc_ip;
										*(int*)(((char*)&data) + 8)  = inet_addr("255.255.255.0");
										*(int*)(((char*)&data) + 12) = inet_addr("10.0.0.1");
										*(int*)(((char*)&data) + 16) = htonl(MAX_MTU);
										memcpy((((char*)&data) + 20), key, sizeof(key));

										chip_peer_send(peer, data, sizeof(data), RELIABLE);
									}
									console_log("Client Logged In");
								} else {
									chip_peer_disconnect(peer);
								}
							}
						}
						break;
						case VPN_TYPE_ASSIGN: {
							if(!is_server) {
								uint32_t peer_ip      = *(uint32_t*)(p_data + 0);
								uint32_t peer_subnet  = *(uint32_t*)(p_data + 4);
								uint32_t peer_gateway = *(uint32_t*)(p_data + 8);
								uint32_t peer_mtu     = *(uint32_t*)(p_data + 12);
								char*    peer_key     =  (char*)(p_data + 16);

								setifip(tun, peer_ip, peer_subnet, peer_mtu);
								ifup(tun);
				
								console_log("Assigned: ip [%i.%i.%i.%i] gateway [%i.%i.%i.%i]", (peer_ip >> 0) & 0xFF, (peer_ip >> 8) & 0xFF, (peer_ip >> 16) & 0xFF, (peer_ip >> 24) & 0xFF, (peer_gateway >> 0) & 0xFF, (peer_gateway >> 8) & 0xFF, (peer_gateway >> 16) & 0xFF, (peer_gateway >> 24) & 0xFF);

								if(pull_routes) {
									console_log("Setting Routes");
									uint32_t default_gateway = get_default_gateway();
									if(exec_sprintf("ip route add %s via %i.%i.%i.%i", ip, (default_gateway >> 0) & 0xFF, (default_gateway >> 8) & 0xFF, (default_gateway >> 16) & 0xFF, (default_gateway >> 24) & 0xFF)) { }
									if(exec_sprintf("ip route add 0.0.0.0/1 via %i.%i.%i.%i", (peer_gateway >> 0) & 0xFF, (peer_gateway >> 8) & 0xFF, (peer_gateway >> 16) & 0xFF, (peer_gateway >> 24) & 0xFF)) { }
									if(exec_sprintf("ip route add 128.0.0.0/1 via %i.%i.%i.%i", (peer_gateway >> 0) & 0xFF, (peer_gateway >> 8) & 0xFF, (peer_gateway >> 16) & 0xFF, (peer_gateway >> 24) & 0xFF)) { }
								}
								vpn_peer->internal_ip = peer_ip;
								chip_encrypt_set_key(vpn_peer->enc_ctx, peer_key);
							}
						}
						break;
						case VPN_TYPE_DATA: {
							chip_decrypt_buf(vpn_peer->enc_ctx, p_data, size);
							IPPacket *ip_hdr = (IPPacket*)p_data;
							if(
								((ip_hdr->dst_addr == vpn_peer->internal_ip && !is_server) || 
								(ip_hdr->src_addr == vpn_peer->internal_ip && is_server)) && 
								(size > 0 && size <= (MAX_MTU))
							) {
								// Check if source is same as peer(Prevents IP spoofing) and bound packet to mtu size
								if(write(tun->fd, p_data, size)) {}
							}
						}
						break;
					}
					
				}
				break;

				case EVENT_DISCONNECT: {
					
					Peer *peer = event.peer;
					VPNPeer *vpn_peer = ((VPNPeer*)(peer->data));
					chip_decrypt_free(vpn_peer->enc_ctx);
					free(vpn_peer);

					console_log("Disconnected");
					
					if(!is_server) {
						exit(0);
					}
					
				}
				break;

				case EVENT_SOCKET_SELECT: {
					char buf[3000];
					int  *p_type = (int*)&buf;
					char *p_data = ((char*)&buf) + 4;

					int size = read(tun->fd, p_data, sizeof(buf) - 4);

					IPPacket *ip_hdr = (IPPacket*)p_data;

					Peer *peer = chipvpn_get_peer_by_ip(socket, is_server ? ip_hdr->dst_addr : ip_hdr->src_addr);
					if(peer) {
						VPNPeer *vpn_peer = (VPNPeer*)peer->data;
						*p_type = htonl(VPN_TYPE_DATA);
						chip_encrypt_buf(vpn_peer->enc_ctx, p_data, size);
						chip_peer_send(peer, buf, size + 4, DATAGRAM);
					}
				}
				break;

				case EVENT_NONE: {

				}
				break;
			}
		}
	}
}

uint32_t chipvpn_get_peer_free_ip(Socket *socket) {
	uint32_t start = inet_addr("10.0.0.100");
	uint32_t end   = inet_addr("10.0.0.200");
	bool     trip  = false;

	for(uint32_t ip = ntohl(start); ip < ntohl(end); ip++) {
		trip = false;
		for(Peer *peer = socket->peers; peer < &socket->peers[socket->peer_count]; ++peer) {
			if(
				(peer->state == STATE_CONNECTED) && 
				(((VPNPeer*)(peer->data))->internal_ip == htonl(ip))
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

Peer *chipvpn_get_peer_by_ip(Socket *socket, uint32_t ip) {
	for(Peer *peer = socket->peers; peer < &socket->peers[socket->peer_count]; ++peer) {
		if(
			(peer->state == STATE_CONNECTED) && 
			(((VPNPeer*)(peer->data))->internal_ip == ip)
		) {
			return peer;
		}
	}
	return NULL;
}

void chipvpn_fill_pseudo_random(char *src, int len) {
    syscall(SYS_getrandom, src, len, 1);
}
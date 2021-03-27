#include "json/include/cJSON.h"
#include "chipvpn.h"

void chipvpn_event_loop(char *config_file) {
	char     ip[32];
	int      port        = 0;
	char    *token       = NULL;
	bool     is_server   = false;
	bool     pull_routes = false;
	int      max_peers   = 8;

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

	Tun *tun = open_tun("");
	if(tun < 0 || tun  == NULL) {
		error("Tuntap adaptor creation failed, please run as sudo");
	}

	reconnect:;

	CSHost *socket = NULL;

	if(is_server) {
		CSAddress addr;
		addr.ip   = inet_addr(ip);
		addr.port = htons(port);

		if((socket = chip_host_create(&addr, max_peers)) == NULL) {
			error("Unable to create socket");
		}

		setifip(tun, inet_addr("10.0.0.1"), inet_addr("255.255.255.0"), MAX_MTU);
		ifup(tun);
	} else {
		if((socket = chip_host_create(NULL, 1)) == NULL) {
			error("Unable to create socket");
		}

		CSAddress addr;
		addr.ip   = inet_addr(ip);
		addr.port = htons(port);

		console_log("Connecting to %s:%i", ip, port);

		if(!chip_host_connect(socket, &addr)) {
			console_log("Unable to connect, reconnecting");
			sleep(1);
			chip_host_free(socket);
			goto reconnect;
		}
	}

	chip_host_select(socket, tun->fd);

	uint32_t last_update_quota = 0;

	CSEvent event;

	while(1) {
		if((chip_host_event(socket, &event) > 0)) {
			switch(event.type) {
				case EVENT_CONNECT: {
					
					console_log("Connected");

					// Allocate VPN Client
					VPNPeer *vpn_peer   = malloc(sizeof(VPNPeer));
					vpn_peer->is_authed = false;
					vpn_peer->tx = 0; // transmitted
					vpn_peer->rx = 0; // received

					// Bind VPN Client to socket
					CSPeer *peer = event.peer;
					peer->data = (void*)vpn_peer;

					if(!is_server) {
						console_log("Authenticating");
						VPNAuthPacket p_auth;
						memcpy((char*)&p_auth, token, strlen(token));
						chipvpn_peer_send(peer, VPN_TYPE_AUTH, &p_auth, strlen(token));
					}
					
				}
				break;

				case EVENT_RECEIVE: {
					if(event.size > sizeof(VPNPacket)) {
						break;
					}

					VPNPacket    *r_packet = (VPNPacket*)event.data;
					VPNPacketType r_type   = ntohl(r_packet->header.type);
					uint32_t      r_size   = ntohl(r_packet->header.size);
				
					CSPeer *peer = event.peer;
					VPNPeer *vpn_peer = ((VPNPeer*)(peer->data));

					if(r_size > sizeof(r_packet->data)) {
						chip_peer_disconnect(peer);
						break;
					}

					switch(r_type) {
						case VPN_TYPE_AUTH: {
							if(is_server) {
								VPNAuthPacket p_auth = r_packet->data.p_auth;
								if(r_size == strlen(token) && memcmp(p_auth.token, token, strlen(token)) == 0) {
									uint32_t alloc_ip = chipvpn_get_peer_free_ip(socket);
									if(alloc_ip > 0) {
										vpn_peer->uid = chipvpn_crc32b(p_auth.token, r_size);
										vpn_peer->internal_ip = alloc_ip;

										VPNAssignPacket data;
										data.ip      = alloc_ip;
										data.subnet  = inet_addr("255.255.255.0");
										data.gateway = inet_addr("10.0.0.1");
										data.mtu     = htonl(MAX_MTU);
										chipvpn_peer_send(peer, VPN_TYPE_ASSIGN, &data, sizeof(data));
										
										vpn_peer->is_authed = true;
										console_log("Client Logged In %u", vpn_peer->uid);
									} else {
										chip_peer_disconnect(peer);
									}
								} else {
									chip_peer_disconnect(peer);
								}
							}
						}
						break;
						case VPN_TYPE_ASSIGN: {
							VPNAssignPacket p_assign = r_packet->data.p_assign;
							if(!is_server) {
								uint32_t peer_ip      = (p_assign.ip);
								uint32_t peer_subnet  = (p_assign.subnet);
								uint32_t peer_gateway = (p_assign.gateway);
								uint32_t peer_mtu     = ntohl(p_assign.mtu);

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
								vpn_peer->uid = chipvpn_crc32b(token, strlen(token));
								vpn_peer->is_authed = true;
								vpn_peer->internal_ip = peer_ip;
								console_log("initialization Sequence Complete");
							}
						}
						break;
						case VPN_TYPE_DATA: {
							VPNDataPacket p_data = r_packet->data.p_data;
							chip_decrypt_buf((char*)&p_data, r_size);
							IPPacket *ip_hdr = (IPPacket*)(&p_data);
							if(
								vpn_peer->is_authed == true &&
								((ip_hdr->dst_addr == vpn_peer->internal_ip && !is_server) || 
								(ip_hdr->src_addr == vpn_peer->internal_ip && is_server)) && 
								(r_size > 0 && r_size <= (MAX_MTU))
								
							) {
								// Check if source is same as peer(Prevents IP spoofing) and bound packet to mtu size
								vpn_peer->rx += r_size;
								if(write(tun->fd, (char*)&p_data, r_size)) {}
							}
						}
						break;
					}
					
				}
				break;

				case EVENT_DISCONNECT: {
					CSPeer *peer = event.peer;
					VPNPeer *vpn_peer = ((VPNPeer*)(peer->data));
					free(vpn_peer);

					console_log("Disconnected");
					
					if(!is_server) {
						console_log("Reconnecting...");
						sleep(1);
						chip_host_free(socket);
						goto reconnect;
					}
					
				}
				break;

				case EVENT_SOCKET_SELECT: {
					VPNDataPacket packet;

					int size = read(tun->fd, (char*)&packet, sizeof(packet));

					IPPacket *ip_hdr = (IPPacket*)&packet;

					CSPeer *peer = chipvpn_get_peer_by_ip(socket, is_server ? ip_hdr->dst_addr : ip_hdr->src_addr);
					if(peer) {
						VPNPeer *vpn_peer = (VPNPeer*)peer->data;
						if(vpn_peer->is_authed == true) {
							vpn_peer->tx += size;
							chip_encrypt_buf((char*)&packet, size);
							chipvpn_peer_send(peer, VPN_TYPE_DATA, &packet, size);
						}
					}
				}
				break;

				case EVENT_NONE: {

				}
				break;
			}
		}

		if((chip_proto_get_time() - last_update_quota) >= 2) {
			FILE *quota = fopen("/tmp/chipvpn_quota.txt", "w+");
			if(quota) {
				fprintf(quota, "[\n");
				for(CSPeer *peer = socket->peers; peer < &socket->peers[socket->peer_count]; ++peer) {
					if((peer->state == STATE_CONNECTED)) {
						VPNPeer *vpn_peer = (VPNPeer*)(peer->data);
						fprintf(quota, "\t{\n");
						fprintf(quota, "\t\t\"uid\": \"%u\",\n", vpn_peer->uid);
						fprintf(quota, "\t\t\"tx\": \"%s\",\n", chipvpn_bytes_pretty_print(vpn_peer->tx));
						fprintf(quota, "\t\t\"rx\": \"%s\"\n", chipvpn_bytes_pretty_print(vpn_peer->rx));
						fprintf(quota, "\t},\n");
					}
				}
				fprintf(quota, "]\n");
				fclose(quota);
			}
			last_update_quota = chip_proto_get_time();
		}
	}
}

uint32_t chipvpn_get_peer_free_ip(CSHost *socket) {
	uint32_t start = inet_addr("10.0.0.100");
	uint32_t end   = inet_addr("10.0.0.200");
	bool     trip  = false;

	for(uint32_t ip = ntohl(start); ip < ntohl(end); ip++) {
		trip = false;
		for(CSPeer *peer = socket->peers; peer < &socket->peers[socket->peer_count]; ++peer) {
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

void chipvpn_peer_send(CSPeer *peer, VPNPacketType type, void *data, int size) {
	VPNPacket packet;
	packet.header.type = htonl(type);
	packet.header.size = htonl(size);
	memcpy((char*)&packet.data, data, size);
	chip_peer_send(peer, (char*)&packet, size + sizeof(packet.header));
}

CSPeer *chipvpn_get_peer_by_ip(CSHost *host, uint32_t ip) {
	for(CSPeer *peer = host->peers; peer < &host->peers[host->peer_count]; ++peer) {
		if(
			(peer->state == STATE_CONNECTED) && 
			(((VPNPeer*)(peer->data))->internal_ip == ip)
		) {
			return peer;
		}
	}
	return NULL;
}

CSPeer *chipvpn_get_peer_by_uid(CSHost *host, uint32_t uid) {
	for(CSPeer *peer = host->peers; peer < &host->peers[host->peer_count]; ++peer) {
		if(
			(peer->state == STATE_CONNECTED) && 
			(((VPNPeer*)(peer->data))->uid == uid)
		) {
			return peer;
		}
	}
	return NULL;
}

static const char *chipvpn_bytes_pretty_print(uint64_t bytes) {
	char *suffix[] = {"B", "KB", "MB", "GB", "TB", "PB", "EB"};
	char length = sizeof(suffix) / sizeof(suffix[0]);

	int i = 0;
	double dblBytes = bytes;

	if (bytes > 1024) {
		for (i = 0; (bytes / 1024) > 0 && i<length-1; i++, bytes /= 1024)
			dblBytes = bytes / 1024.0;
	}

	static char output[200];
	sprintf(output, "%.05lf %s", dblBytes, suffix[i]);
	return output;
}

unsigned int chipvpn_crc32b(unsigned char *message, int size) {
   int i, j;
   unsigned int byte, crc, mask;

   i = 0;
   crc = 0xFFFFFFFF;
   for(int i = 0; i < size; i++) {
      byte = message[i];            // Get next byte.
      crc = crc ^ byte;
      for (j = 7; j >= 0; j--) {    // Do eight times.
         mask = -(crc & 1);
         crc = (crc >> 1) ^ (0xEDB88320 & mask);
      }
   }
   return ~crc;
}
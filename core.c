#include "chipvpn.h"

void run_core(char *config) {
	if (signal(SIGINT, stop_core) == SIG_ERR) {
		error("Unable to Setup Signal Handlers");
	}

	FILE *fp = fopen(config, "rb");

	if(!fp) {
		error("Unable to load config");
	}

	char *server_ip          = read_string(fp, "ip");
	char *server_port        = read_string(fp, "port");
	char *server_token       = read_string(fp, "token");
	bool  server_pull_routes = read_bool(fp, "pull_routes");
	bool  is_server          = read_bool(fp, "bind");
	int   server_max_peers   = read_int(fp, "max_peers");

	if(!server_ip || !server_port) {
		error("Server ip or port is not defined in the config");
	}
	if(server_max_peers < 1) {
		server_max_peers = 1;
	}
	if(!server_token) {
		error("Token is not defined");
	}

	fclose(fp);

	Tun *tun = open_tun("");
	if(tun < 0 || tun  == NULL) {
		error("VPN socket creation failed, run as sudo");
	}

	Socket *socket;

	if(!is_server) {
		socket = chip_host_create(1);
		if(!socket) {
			error("Unable to create socket");
		}
		if(!chip_host_connect(socket, server_ip, atoi(server_port))) {
			error("Unable to init connection with server");
		}
	} else {
		socket = chip_host_create(server_max_peers);
		if(!socket) {
			error("Unable to create socket");
		}
		if(!chip_host_bind(socket, server_ip, atoi(server_port))) {
			error("Bind failed");
		}
		setifip(tun, inet_addr("10.0.0.1"), inet_addr("255.255.255.0"), MAX_MTU);
		ifup(tun);
	}

	char key[] = {
		0xaa, 0xdd, 0xb9, 0x46, 0x82, 0x03, 0xcf, 0xc6, 
		0xf9, 0xe6, 0x87, 0x41, 0xe4, 0xf1, 0x32, 0xcb, 
		0x23, 0xef, 0x58, 0xf0, 0xb0, 0x07, 0x86, 0xf7, 
		0x60, 0x6a, 0xfc, 0x35, 0xe8, 0x40, 0xe0, 0x04, 
		0x58, 0xaa, 0x74, 0x55, 0x27, 0xd3, 0x79, 0x3f, 
		0x11, 0x3f, 0x96, 0x5c, 0xc2, 0x85, 0xd0, 0x34, 
		0x3e, 0x8f, 0xcb, 0x30, 0x84, 0x39, 0x7e, 0x87, 
		0x3e, 0xa1, 0x43, 0x71, 0xa0, 0xe6, 0x67, 0x60
	};

	fd_set rdset;
	struct timeval tv;
	SocketEvent event;

	while(1) {
		tv.tv_sec  = PING_INTERVAL;
		tv.tv_usec = 0;

		FD_ZERO(&rdset);
		FD_SET(tun->fd, &rdset);
		FD_SET(chip_host_get_fd(socket), &rdset);

		select(max(tun->fd, chip_host_get_fd(socket)) + 1, &rdset, NULL, NULL, &tv);

		while((chip_host_event(socket, &event) > 0)) {
			switch(event.type) {
				case EVENT_CONNECT: {
					console_log("Connected");
					Peer *peer = event.peer;
					peer->data = (void*)malloc(sizeof(VPNPeer));

					if(!is_server) {
						char data[8];
						*(int*)(((char*)&data) + 0) = htonl(VPN_TYPE_AUTH);
						*(int*)(((char*)&data) + 4) = htonl(54678762);
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
								uint32_t token = ntohl(*(uint32_t*)(p_data + 0));
								if(token != 54678762) {
									chip_peer_disconnect(peer);
									break;
								}
								uint32_t alloc_ip = get_peer_free_ip(socket);
								if(alloc_ip > 0) {
									char data[3000];
									vpn_peer->internal_ip = alloc_ip;

									*(int*)(((char*)&data) + 0) = htonl(VPN_TYPE_ASSIGN);
									*(int*)(((char*)&data) + 4) = alloc_ip;
									*(int*)(((char*)&data) + 8) = inet_addr("255.255.255.0");
									*(int*)(((char*)&data) + 12) = inet_addr("10.0.0.1");
									*(int*)(((char*)&data) + 16) = htonl(MAX_MTU);

									chip_peer_send(peer, data, sizeof(data), RELIABLE);
								}
								console_log("Client Logged In");
							}
						}
						break;
						case VPN_TYPE_ASSIGN: {
							if(!is_server) {
								uint32_t peer_ip      = *(uint32_t*)(p_data + 0);
								uint32_t peer_subnet  = *(uint32_t*)(p_data + 4);
								uint32_t peer_gateway = *(uint32_t*)(p_data + 8);
								uint32_t peer_mtu     = *(uint32_t*)(p_data + 12);

								setifip(tun, peer_ip, peer_subnet, peer_mtu);
								ifup(tun);
				
								console_log("Assigned: ip %i.%i.%i.%i gateway %i.%i.%i.%i", (peer_ip >> 0) & 0xFF, (peer_ip >> 8) & 0xFF, (peer_ip >> 16) & 0xFF, (peer_ip >> 24) & 0xFF, (peer_gateway >> 0) & 0xFF, (peer_gateway >> 8) & 0xFF, (peer_gateway >> 16) & 0xFF, (peer_gateway >> 24) & 0xFF);

								if(server_pull_routes) {
									uint32_t default_gateway = get_default_gateway();
									if(exec_sprintf("ip route add %s via %i.%i.%i.%i", server_ip, (default_gateway >> 0) & 0xFF, (default_gateway >> 8) & 0xFF, (default_gateway >> 16) & 0xFF, (default_gateway >> 24) & 0xFF)) { }
									if(exec_sprintf("ip route add 0.0.0.0/1 via %i.%i.%i.%i", (peer_gateway >> 0) & 0xFF, (peer_gateway >> 8) & 0xFF, (peer_gateway >> 16) & 0xFF, (peer_gateway >> 24) & 0xFF)) { }
									if(exec_sprintf("ip route add 128.0.0.0/1 via %i.%i.%i.%i", (peer_gateway >> 0) & 0xFF, (peer_gateway >> 8) & 0xFF, (peer_gateway >> 16) & 0xFF, (peer_gateway >> 24) & 0xFF)) { }
								}
								vpn_peer->internal_ip = peer_ip;
							}
						}
						break;
						case VPN_TYPE_DATA: {
							decrypt((char*)&key, p_data, size);
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
					free(event.data);
				}
				break;

				case EVENT_DISCONNECT: {
					Peer *peer = event.peer;
					VPNPeer *vpn_peer = ((VPNPeer*)(peer->data));

					free(vpn_peer);

					console_log("Disconnected");
					
					if(!is_server) {
						console_log("Reconnecting");
						chip_host_connect(socket, server_ip, atoi(server_port));
					}
				}
				break;

				case EVENT_CONNECT_TIMEOUT: {
					if(!is_server) {
						console_log("Timeout, Reconnecting");
						chip_host_connect(socket, server_ip, atoi(server_port));
					}
				}
				break;

				case EVENT_NONE: {

				}
				break;
			}
		}

		if(FD_ISSET(tun->fd, &rdset)) {
			char buf[3000];
			int  *p_type = (int*)&buf;
			char *p_data = ((char*)&buf) + 4;

			int size = read(tun->fd, p_data, sizeof(buf) - 4);

			IPPacket *ip_hdr = (IPPacket*)p_data;

			Peer *peer = get_peer_by_ip(socket, is_server ? ip_hdr->dst_addr : ip_hdr->src_addr);
			if(peer) {
				*p_type = htonl(VPN_TYPE_DATA);
				encrypt((char*)&key, p_data, size);
				chip_peer_send(peer, buf, size + 4, DATAGRAM);
			}
		}
	}
}

uint32_t get_peer_free_ip(Socket *socket) {
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

Peer *get_peer_by_ip(Socket *socket, uint32_t ip) {
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

void stop_core() {
	exit(0);
}
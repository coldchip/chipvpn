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
		socket = new_socket(1);
		if(!socket) {
			error("Unable to create socket");
		}
		socket_connect(socket, server_ip, atoi(server_port));
	} else {
		socket = new_socket(server_max_peers);
		if(!socket) {
			error("Unable to create socket");
		}
		if(!socket_bind(socket, server_ip, atoi(server_port))) {
			error("Bind failed");
		}
		setifip(tun, inet_addr("10.0.0.1"), inet_addr("255.255.255.0"), MAX_MTU);
		ifup(tun);
	}

	uint64_t tx = 0;
	uint64_t rx = 0;
	fd_set rdset;
	struct timeval tv;
	SocketEvent event;

	while(1) {
		tv.tv_sec  = PING_INTERVAL;
		tv.tv_usec = 0;

		FD_ZERO(&rdset);
		FD_SET(tun->fd, &rdset);
		FD_SET(get_socket_fd(socket), &rdset);

		select(max(tun->fd, get_socket_fd(socket)) + 1, &rdset, NULL, NULL, &tv);

		while((socket_event(socket, &event) > 0)) {
			switch(event.type) {
				case EVENT_CONNECT: {
					if(is_server) {
						uint32_t alloc_ip = get_peer_free_ip(&socket->peers);
						if(alloc_ip > 0) {
							char data[3000];
							event.peer->internal_ip  = alloc_ip;

							uint32_t tun_ip        = alloc_ip;
							uint32_t tun_subnet    = inet_addr("255.255.255.0");
							uint32_t tun_gateway   = inet_addr("10.0.0.1");
							uint32_t mtu           = htonl(MAX_MTU);

							memcpy(((char*)&data) + (sizeof(uint32_t) * 0) + 4, &tun_ip,        sizeof(tun_ip));
							memcpy(((char*)&data) + (sizeof(uint32_t) * 1) + 4, &tun_subnet,    sizeof(tun_subnet));
							memcpy(((char*)&data) + (sizeof(uint32_t) * 2) + 4, &tun_gateway,   sizeof(tun_gateway));
							memcpy(((char*)&data) + (sizeof(uint32_t) * 3) + 4, &mtu,           sizeof(mtu));

							int p_type = htonl(69);
							memcpy((char*)&data, &p_type, sizeof(p_type));

							socket_peer_send(event.peer, data, sizeof(data), RELIABLE);
						}
						printf("Client Connected\n");
					} else {
						printf("Connected to server\n");
					}
				}
				break;

				case EVENT_RECEIVE: {
					int  p_type = ntohl(*(int*)event.data);
					char *p_data = ((char*)event.data) + 4;
					int size = event.size - 4;
					switch(p_type) {
						case 69: {
							printf("received DHCP \n");
							uint32_t peer_ip      = *(uint32_t*)(p_data);
							uint32_t peer_subnet  = *(uint32_t*)(p_data += sizeof(uint32_t));
							uint32_t peer_gateway = *(uint32_t*)(p_data += sizeof(uint32_t));
							uint32_t peer_mtu     = *(uint32_t*)(p_data += sizeof(uint32_t));

							setifip(tun, peer_ip, peer_subnet, peer_mtu);
							ifup(tun);

							if(server_pull_routes) {
								uint32_t default_gateway = get_default_gateway();
								if(exec_sprintf("ip route add %s via %i.%i.%i.%i", server_ip, (default_gateway >> 0) & 0xFF, (default_gateway >> 8) & 0xFF, (default_gateway >> 16) & 0xFF, (default_gateway >> 24) & 0xFF)) { }
								if(exec_sprintf("ip route add 0.0.0.0/1 via %i.%i.%i.%i", (peer_gateway >> 0) & 0xFF, (peer_gateway >> 8) & 0xFF, (peer_gateway >> 16) & 0xFF, (peer_gateway >> 24) & 0xFF)) { }
								if(exec_sprintf("ip route add 128.0.0.0/1 via %i.%i.%i.%i", (peer_gateway >> 0) & 0xFF, (peer_gateway >> 8) & 0xFF, (peer_gateway >> 16) & 0xFF, (peer_gateway >> 24) & 0xFF)) { }
							}
							event.peer->internal_ip = peer_ip;
						}
						break;
						case 32: {
							IPPacket *ip_hdr = (IPPacket*)p_data;
							if(
								((ip_hdr->dst_addr == event.peer->internal_ip && !is_server) || 
								(ip_hdr->src_addr == event.peer->internal_ip && is_server)) && 
								(size > 0 && size <= (MAX_MTU))
							) {
								// Check if source is same as peer(Prevents IP spoofing) and bound packet to mtu size
								rx += size;
								event.peer->rx += size;
								if(write(tun->fd, p_data, size)) {}
							}
						}
						break;
					}

					free(event.data);
				}
				break;

				case EVENT_DISCONNECT: {
					printf("Disconnected\n");
					if(!is_server) {
						printf("Reconnecting\n");
						socket_connect(socket, server_ip, atoi(server_port));
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

			Peer *peer = get_peer_by_ip(&socket->peers, is_server ? ip_hdr->dst_addr : ip_hdr->src_addr);
			if(peer) {
				tx += size;
				peer->tx += size;
				*p_type = htonl(32);

				socket_peer_send(peer, buf, size + 4, DATAGRAM);
			}
		}
	}
}

void stop_core() {
	exit(0);
}
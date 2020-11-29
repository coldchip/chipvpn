#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <math.h>
#include "sha1.h"
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

	Socket *socket = new_socket();

	if(!socket) {
		error("Unable to create socket");
	}

	if(!is_server) {
		socket_connect(socket, server_ip, atoi(server_port));
	} else {
		setifip(tun, "10.0.0.1", "255.255.255.0", MAX_MTU);
		ifup(tun);

		if(!socket_bind(socket, server_ip, atoi(server_port))) {
			error("Bind failed");
		}
	}

	int last_ping = 0;
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

		if((time(NULL) - last_ping) >= PING_INTERVAL) {
			socket_service(socket);
			last_ping = time(NULL);
		}

		if(FD_ISSET(get_socket_fd(socket), &rdset)) {
			int size = socket_event(socket, &event);
			if(size > 0) {
				switch(event.type) {
					case EVENT_CONNECT: {
						if(is_server) {
							uint32_t alloc_ip = get_peer_free_ip(&socket->peers);
							if(alloc_ip > 0) {
								char data[3000];
								event.peer->internal_ip  = alloc_ip;

								uint32_t tun_ip        = htonl(alloc_ip);
								uint32_t tun_subnet    = htonl(inet_addr("255.255.255.0"));
								uint32_t tun_gateway   = htonl(inet_addr("10.0.0.1"));
								uint32_t mtu           = htonl(MAX_MTU);

								memcpy(((char*)&data) + (sizeof(uint32_t) * 0) + 4, &tun_ip,        sizeof(tun_ip));
								memcpy(((char*)&data) + (sizeof(uint32_t) * 1) + 4, &tun_subnet,    sizeof(tun_subnet));
								memcpy(((char*)&data) + (sizeof(uint32_t) * 2) + 4, &tun_gateway,   sizeof(tun_gateway));
								memcpy(((char*)&data) + (sizeof(uint32_t) * 3) + 4, &mtu,           sizeof(mtu));

								int p_type = htonl(69);
								memcpy((char*)&data, &p_type, sizeof(p_type));

								socket_peer_send(socket, event.peer, data, sizeof(data), RELIABLE);
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
								char data[3000];
								uint32_t peer_ip;
								uint32_t peer_subnet;
								uint32_t peer_gateway;
								uint32_t peer_mtu;
								memcpy(&peer_ip,      (p_data) + (sizeof(uint32_t) * 0), sizeof(int));
								memcpy(&peer_subnet,  (p_data) + (sizeof(uint32_t) * 1), sizeof(int));
								memcpy(&peer_gateway, (p_data) + (sizeof(uint32_t) * 2), sizeof(int));
								memcpy(&peer_mtu,     (p_data) + (sizeof(uint32_t) * 3), sizeof(int));

								peer_ip      = ntohl(peer_ip); 
								peer_subnet  = ntohl(peer_subnet); 
								peer_gateway = ntohl(peer_gateway); 
								peer_mtu     = ntohl(peer_mtu);

								char set_ip[INET_ADDRSTRLEN];
								char set_subnet[INET_ADDRSTRLEN];
								char set_gateway[INET_ADDRSTRLEN];
								sprintf(set_ip,      "%i.%i.%i.%i", (peer_ip >> 0)      & 0xFF, (peer_ip >> 8)      & 0xFF, (peer_ip >> 16)      & 0xFF, (peer_ip >> 24)      & 0xFF);
								sprintf(set_subnet,  "%i.%i.%i.%i", (peer_subnet >> 0)  & 0xFF, (peer_subnet >> 8)  & 0xFF, (peer_subnet >> 16)  & 0xFF, (peer_subnet >> 24)  & 0xFF);
								sprintf(set_gateway, "%i.%i.%i.%i", (peer_gateway >> 0) & 0xFF, (peer_gateway >> 8) & 0xFF, (peer_gateway >> 16) & 0xFF, (peer_gateway >> 24) & 0xFF);
								printf("%s\n", set_ip);

								setifip(tun, set_ip, set_subnet, peer_mtu);
								ifup(tun);

								if(server_pull_routes) {
									char default_gateway[16];
									get_default_gateway((char*)&default_gateway);
									if(exec_sprintf("ip route add %s via %s", server_ip, default_gateway)) { }
									if(exec_sprintf("ip route add 0.0.0.0/1 via %s", set_gateway)) { }
									if(exec_sprintf("ip route add 128.0.0.0/1 via %s", set_gateway)) { }
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

					case EVENT_NONE: {

					}
					break;
				}
			}
		}

		if(FD_ISSET(tun->fd, &rdset)) {
			char buf[3000];
			int  *p_type = (int*)&buf;
			char *p_data = ((char*)&buf) + 4;

			int size = read(tun->fd, p_data, sizeof(buf) - 4);

			IPPacket *ip_hdr = (IPPacket*)p_data;

			Peer *peer = NULL;
			if(!is_server) {
				peer = get_peer_by_ip(&socket->peers, ip_hdr->src_addr);
			} else {
				peer = get_peer_by_ip(&socket->peers, ip_hdr->dst_addr);
			}
			if(peer) {
				tx += size;
				peer->tx += size;
				*p_type = htonl(32);

				socket_peer_send(socket, peer, buf, size + 4, DATAGRAM);
			}
		}
	}
}

void print_console(Status status, char *server_ip, char *server_port, bool is_server, uint64_t tx, uint64_t rx, int peers, char *dev) {
	struct winsize w;
	ioctl(0, TIOCGWINSZ, &w);
	printf("\033[0;0H");
	for(int i = 0; i < 1920; i++) {
		printf(" ");
	}
	printf("\033[0;0H");
	if(!is_server) {
		printf("\033[1;36mChipVPN Client\033[0m by ColdChip\n\n");
	} else {
		printf("\033[1;36mChipVPN Server\033[0m by ColdChip\n\n");
	}

	printf("\x1b[32mStatus   ");
	switch(status) {
		case STATE_DISCONNECTED: {
			printf("\x1b[31m%*s%s", w.ws_col / 3, "", "disconnected");
		}
		break;
		case STATE_CONNECTING: {
			printf("\x1b[33m%*s%s", w.ws_col / 3, "", "connecting");
		}
		break;
		case STATE_CONNECTED: {
			printf("\x1b[32m%*s%s", w.ws_col / 3, "", "connected");
		}
		break;
		case STATE_ONLINE: {
			printf("\x1b[32m%*s%s", w.ws_col / 3, "", "online");
		}
		break;
		default: {
			printf("\x1b[32m%*s%s", w.ws_col / 3, "", "unknown");
		}
		break;
	}
	printf("\033[0m\n");
	if(is_server) {
		printf("Bind     ");
		printf("%*s%s:%s\n", w.ws_col / 3, "", server_ip, server_port);
	} else {
		printf("Server   ");
		printf("%*s%s:%s\n", w.ws_col / 3, "", server_ip, server_port);
	}
	printf("Region   ");
	printf("%*s%s\n", w.ws_col / 3, "", "Singapore");
	printf("Interface");
	printf("%*s%s\n", w.ws_col / 3, "", dev);
	if(is_server) {
		printf("Peers    ");
		printf("%*s%i\n", w.ws_col / 3, "", peers);
	}
	char *format_tx = format_size(tx);
	char *format_rx = format_size(rx);

	printf("Sent     ");
	printf("%*s%s\n", w.ws_col / 3, "", format_tx);
	printf("Received ");
	printf("%*s%s\n", w.ws_col / 3, "", format_rx);

	free(format_tx); 
	free(format_rx);
}

void stop_core() {
	exit(0);
}
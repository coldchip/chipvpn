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
#include "sha1.h"
#include "chipvpn.h"

void connect_server(Socket *socket, struct sockaddr_in addr, char *token) {
	Packet packet;
	memset(&packet, 0, sizeof(Packet));
	packet.header.type    = htonl(CONNECT_REQUEST);
	packet.header.size    = htonl(0);
	int timestamp = time(NULL);
	char temp[strlen(token) + sizeof(int)];
	memcpy(temp, token, strlen(token));
	memcpy(temp + strlen(token), &timestamp, sizeof(int));
	SHA1((char*)&packet.data, temp, sizeof(temp));
	send_peer(socket, rand(), (char*)&packet, sizeof(Packet), &addr, RELIABLE);
}

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

	struct sockaddr_in     addr;
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = inet_addr(server_ip); 
	addr.sin_port        = htons(atoi(server_port));

	Socket *socket = new_socket();

	if(!socket) {
		error("Unable to create socket");
	}

	List peers;
	list_clear(&peers);

	Status status;

	if(!is_server) {
		status = STATE_DISCONNECTED;
		connect_server(socket, addr, server_token);
	} else {
		status = STATE_ONLINE;
		setifip(tun, "10.0.0.1", "255.255.255.0", MAX_MTU);
		ifup(tun);
		struct sockaddr_in      baddr;
		baddr.sin_family      = AF_INET;
		baddr.sin_addr.s_addr = inet_addr(server_ip); 
		baddr.sin_port        = htons(atoi(server_port));

		if(!socket_bind(socket, baddr)) {
			error("Bind failed");
		}
	}

	int last_ping = 0;
	uint64_t tx = 0;
	uint64_t rx = 0;
	fd_set rdset;
	struct timeval tv;
	Packet packet;

	while(1) {
		tv.tv_sec  = PING_INTERVAL;
		tv.tv_usec = 0;

		FD_ZERO(&rdset);
		FD_SET(tun->fd, &rdset);
		FD_SET(get_socket_fd(socket), &rdset);

		select(max(tun->fd, get_socket_fd(socket)) + 1, &rdset, NULL, NULL, &tv);

		if((time(NULL) - last_ping) >= PING_INTERVAL) {
			socket_service(socket);
			int count = 0;
			ListNode *i = list_begin(&peers);
			while(i != list_end(&peers)) {
				Peer *peer = (Peer*)i;

				i = list_next(i);

				count++;
				memset(&packet, 0, sizeof(Packet));
				packet.header.type    = htonl(PING);
				packet.header.size    = htonl(0);
				packet.header.session = peer->session;
				send_peer(socket, rand(), (char*)&packet, sizeof(PacketHeader), &peer->addr, RELIABLE);
				
				if(is_unpinged(peer)) {
					list_remove(&peer->node);
					free(peer);
					if(!is_server) {
						status = STATE_DISCONNECTED;
					}
				}
			}
			last_ping = time(NULL);

			print_console(status, server_ip, server_port, is_server, tx, rx, count, tun->dev);
		
			if(!is_server && status == STATE_DISCONNECTED) {
				connect_server(socket, addr, server_token);
			}
		}

		if(FD_ISSET(get_socket_fd(socket), &rdset)) {
			memset(&packet, 0, sizeof(Packet));
			if(!recv_peer(socket, (char*)&packet, sizeof(Packet), &addr)) {
				continue;
			}

			int     packet_type    = ntohl(packet.header.type);
			int     packet_size    = ntohl(packet.header.size);
			Session packet_session = packet.header.session;

			Peer *peer = get_peer_by_session(&peers, packet_session);
			if(peer) {
				// Update peer address
				peer->addr = addr;
			}

			if(packet_type == CONNECT_RESPONSE && !is_server) {
				if(list_size(&peers) >= 1) {
					continue;
				}
				Peer *peer_alloc = malloc(sizeof(Peer));

				list_insert(list_end(&peers), peer_alloc);

				uint32_t peer_ip;
				uint32_t peer_subnet;
				uint32_t peer_gateway;
				uint32_t peer_mtu;
				memcpy(&peer_ip,      ((char*)&packet.data) + (sizeof(uint32_t) * 0), sizeof(int));
				memcpy(&peer_subnet,  ((char*)&packet.data) + (sizeof(uint32_t) * 1), sizeof(int));
				memcpy(&peer_gateway, ((char*)&packet.data) + (sizeof(uint32_t) * 2), sizeof(int));
				memcpy(&peer_mtu,     ((char*)&packet.data) + (sizeof(uint32_t) * 3), sizeof(int));
				memcpy(peer_alloc->key, ((char*)&packet.data) + (sizeof(uint32_t) * 4), 64);

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
				
				setifip(tun, set_ip, set_subnet, peer_mtu);
				ifup(tun);

				if(server_pull_routes) {
					char default_gateway[16];
					get_default_gateway((char*)&default_gateway);
					if(exec_sprintf("ip route add %s via %s", server_ip, default_gateway)) {
						//error("Set path failed");
					}
					if(exec_sprintf("ip route add 0.0.0.0/1 via %s", set_gateway)) {
						//error("Set path failed");
					}
					if(exec_sprintf("ip route add 128.0.0.0/1 via %s", set_gateway)) {
						//error("Set path failed");
					}
				}

				peer_alloc->internal_ip = peer_ip;
				peer_alloc->addr        = addr;
				peer_alloc->tx          = 0;
				peer_alloc->rx          = 0;
				peer_alloc->quota       = 5497558138880;
				peer_alloc->session     = packet_session;

				update_ping(peer_alloc);

				status = STATE_CONNECTED;
			} else if(packet_type == CONNECT_REQUEST && is_server) {
				if(list_size(&peers) < server_max_peers) {
					char token[20];
					int timestamp = time(NULL);
					char temp[strlen(server_token) + sizeof(int)];
					memcpy(temp, server_token, strlen(server_token));
					memcpy(temp + strlen(server_token), &timestamp, sizeof(int));
					SHA1(token, temp, sizeof(temp));

					if(memcmp((char*)&packet.data, token, sizeof(token)) == 0) {
						Peer *peer_alloc  = malloc(sizeof(Peer));
						list_insert(list_end(&peers), peer_alloc);

						uint32_t alloc_ip = get_peer_free_ip(&peers);
						if(peer_alloc && alloc_ip != 0) {
							peer_alloc->internal_ip  = alloc_ip;
							peer_alloc->addr         = addr;
							peer_alloc->tx           = 0;
							peer_alloc->rx           = 0;
							peer_alloc->quota        = 5497558138880;

							update_ping(peer_alloc);

							fill_random((char*)&peer_alloc->key    , 64);
							fill_random((char*)&peer_alloc->session, sizeof(Session));

							memset(&packet, 0, sizeof(Packet));
							packet.header.type	   = htonl(CONNECT_RESPONSE);
							packet.header.size	   = htonl(0);
							packet.header.session  = peer_alloc->session;
							uint32_t tun_ip        = htonl(alloc_ip);
							uint32_t tun_subnet    = htonl(inet_addr("255.255.255.0"));
							uint32_t tun_gateway   = htonl(inet_addr("10.0.0.1"));
							uint32_t mtu           = htonl(MAX_MTU);
							memcpy(((char*)&packet.data) + (sizeof(uint32_t) * 0), &tun_ip,        sizeof(tun_ip));
							memcpy(((char*)&packet.data) + (sizeof(uint32_t) * 1), &tun_subnet,    sizeof(tun_subnet));
							memcpy(((char*)&packet.data) + (sizeof(uint32_t) * 2), &tun_gateway,   sizeof(tun_gateway));
							memcpy(((char*)&packet.data) + (sizeof(uint32_t) * 3), &mtu,           sizeof(mtu));
							memcpy(((char*)&packet.data) + (sizeof(uint32_t) * 4), &peer_alloc->key, 	  64);
							send_peer(socket, rand(), (char*)&packet, sizeof(Packet), &peer_alloc->addr, RELIABLE);
						} else {
							memset(&packet, 0, sizeof(Packet));
							packet.header.type = htonl(CONNECTION_REJECTED);
							send_peer(socket, rand(), (char*)&packet, sizeof(Packet), &addr, RELIABLE);
						}
					} else {
						memset(&packet, 0, sizeof(Packet));
						packet.header.type = htonl(LOGIN_FAILED);
						send_peer(socket, rand(), (char*)&packet, sizeof(Packet), &addr, RELIABLE);
					}
				} else {
					memset(&packet, 0, sizeof(Packet));
					packet.header.type = htonl(LOGIN_FAILED);
					send_peer(socket, rand(), (char*)&packet, sizeof(Packet), &addr, RELIABLE);
				}
			} else if(packet_type == DATA) {
				if(peer && (peer->tx + peer->rx) < peer->quota) {
					decrypt(peer->key, (char*)&packet.data, sizeof(PacketData));
					IPPacket *ip_hdr = (IPPacket*)&packet.data;
					if(
						((ip_hdr->dst_addr == peer->internal_ip && !is_server) || 
						(ip_hdr->src_addr == peer->internal_ip && is_server)) && 
						(packet_size > 0 && packet_size <= (MAX_MTU))
					) {
						// Check if source is same as peer(Prevents IP spoofing) and bound packet to mtu size
						rx += packet_size;
						peer->rx += packet_size;
						if(write(tun->fd, (char*)&(packet.data), packet_size)) {}
					}
				}
			} else if(packet_type == PING) {
				if(peer) {
					update_ping(peer);
				}
			} else if(packet_type == LOGIN_FAILED && !is_server) {
				status = STATE_DISCONNECTED;
			} else if(packet_type == CONNECTION_REJECTED && !is_server) {
				status = STATE_DISCONNECTED;
			}
		}

		if(FD_ISSET(tun->fd, &rdset)) {
			memset(&packet, 0, sizeof(Packet));
			int size = read(tun->fd, (char*)&packet.data, sizeof(PacketData));

			IPPacket *ip_hdr = (IPPacket*)&packet.data;

			Peer *peer = NULL;
			if(!is_server) {
				peer = get_peer_by_ip(&peers, ip_hdr->src_addr);
			} else {
				peer = get_peer_by_ip(&peers, ip_hdr->dst_addr);
			}
			if(peer && (peer->tx + peer->rx) < peer->quota) {
				tx += size;
				peer->tx += size;

				packet.header.type    = htonl(DATA);
				packet.header.size    = htonl(size);
				packet.header.session = peer->session;
				encrypt(peer->key, (char*)&(packet.data), sizeof(PacketData));
				send_peer(socket, rand(), (char*)&packet, sizeof(PacketHeader) + size, &peer->addr, DATAGRAM);
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
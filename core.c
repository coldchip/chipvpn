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
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include "sha1.h"
#include "chipvpn.h"

void init_core(bool is_client) {
	if (signal(SIGINT, stop_core) == SIG_ERR) {
		error("Unable to Setup Signal Handlers");
	}

	srand((unsigned) time(NULL));

	Tun *tun = open_tun("");
	if(tun < 0 || tun  == NULL) {
		error("VPN Socket Creation Failed, Run as Sudo");
	}
	if(!is_client) {
		setifip(tun, "10.0.0.1", "255.255.255.0", MAX_MTU);
		ifup(tun);
	}

	run_core(tun, is_client);
}

void connect_server(Socket *socket, struct sockaddr_in addr, char *token) {
	Packet packet;
	memset(&packet, 0, sizeof(Packet));
	packet.header.type = htonl(CONNECT_REQUEST);
	packet.header.size = htonl(0);
	int timestamp = time(NULL);
	char temp[strlen(token) + sizeof(int)];
	memcpy(temp, token, strlen(token));
	memcpy(temp + strlen(token), &timestamp, sizeof(int));
	SHA1((char*)&packet.data, temp, sizeof(temp));
	send_peer(socket, rand(), (char*)&packet, sizeof(Packet), &addr, RELIABLE);
}

void run_core(Tun *tun, bool is_client) {
	FILE *fp = NULL;
	if(is_client == true) {
		fp = fopen("client.conf", "rb");
	} else {
		fp = fopen("server.conf", "rb");
	}

	if(!fp) {
		error("Unable to load config");
	}

	char *server_ip          = read_string(fp, "server");
	char *server_port        = read_string(fp, "port");
	char *server_token       = read_string(fp, "token");
	bool  server_pull_routes = read_bool(fp, "pull_routes");
	int   server_max_peers   = read_int(fp, "max_peers");

	if(!server_ip || !server_port) {
		error("Server ip or port is not defined in the config");
	}
	if(!server_token) {
		error("Token is not defined");
	}

	fclose(fp);

	struct sockaddr_in     addr;
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = inet_addr(server_ip); 
	addr.sin_port        = htons(atoi(server_port));

	Socket *socket = new_socket();

	if(!socket) {
		error("Unable to create socket");
	}

	Peers *peers = new_peer_container(server_max_peers);

	int last_ping  = 0;

	uint64_t tx = 0;
	uint64_t rx = 0;

	fd_set rdset;

	struct timeval tv;

	if(is_client) {
		console_log("Connecting & Authenticating... ");
		connect_server(socket, addr, server_token);
	} else {
		console_log("Binding... ");
		struct sockaddr_in      baddr;
		baddr.sin_family      = AF_INET;
		baddr.sin_addr.s_addr = inet_addr(server_ip); 
		baddr.sin_port        = htons(atoi(server_port));

		if(!socket_bind(socket, baddr)) {
			error("Bind failed");
		}
	}

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
			int i = 0;
			for(Peer *peer = peers->peers; peer < &peers->peers[peers->peerCount]; ++peer) {
				if(is_connected(peer)) {
					i++;
					memset(&packet, 0, sizeof(Packet));
					packet.header.type = htonl(PING);
					packet.header.size = htonl(0);
					packet.header.session = peer->session;
					send_peer(socket, rand(), (char*)&packet, sizeof(PacketHeader), &peer->addr, RELIABLE);
					
					if(is_unpinged(peer)) {
						peer->state = DISCONNECTED;
						if(is_client) {
							printf("\n");
							warning("No Ping Received, Reconnecting to Server");
							sleep(1);
							connect_server(socket, addr, server_token);
						}
					}
				}
			}
			last_ping = time(NULL);

			char *format_tx = format_size(tx);
			char *format_rx = format_size(rx);

			struct winsize w;
			ioctl(0, TIOCGWINSZ, &w);
			printf("\033[0;0H");
			for(int i = 0; i < 1920; i++) {
				printf(" ");
			}
			printf("\033[0;0H");
			if(!is_client) {
				printf("\033[1;36mChipVPN Client\033[0m by ColdChip\n\n");
			} else {
				printf("\033[1;36mChipVPN Server\033[0m by ColdChip\n\n");
			}

			printf("\x1b[32mStatus   ");
			printf("%*s%s\n", w.ws_col / 3, "", "online\033[0m");
			printf("Region   ");
			printf("%*s%s\n", w.ws_col / 3, "", "Singapore");
			printf("Interface");
			printf("%*s%s\n", w.ws_col / 3, "", tun->dev);
			if(!is_client) {
				printf("Peers    ");
				printf("%*s%i\n", w.ws_col / 3, "", i);
			}
			printf("Sent     ");
			printf("%*s%s\n", w.ws_col / 3, "", format_tx);
			printf("Received ");
			printf("%*s%s\n", w.ws_col / 3, "", format_rx);

			free(format_tx);
			free(format_rx);
		}

		if(FD_ISSET(get_socket_fd(socket), &rdset)) {
			memset(&packet, 0, sizeof(Packet));
			if(!recv_peer(socket, (char*)&packet, sizeof(Packet), &addr)) {
				continue;
			}

			int     packet_type    = ntohl(packet.header.type);
			int     packet_size    = ntohl(packet.header.size);
			Session packet_session = packet.header.session;

			Peer *peer = get_peer_by_session(peers, packet_session);
			if(peer) {
				// Update peer address
				peer->addr = addr;
			}

			if(packet_type == CONNECT_RESPONSE && is_client) {
				Peer *peer = get_disconnected_peer(peers);
				if(peer) {
					int peer_ip;
					int peer_subnet;
					int peer_gateway;
					int peer_mtu;
					memcpy(&peer_ip,      ((char*)&packet.data) + (sizeof(int) * 0), sizeof(int));
					memcpy(&peer_subnet,  ((char*)&packet.data) + (sizeof(int) * 1), sizeof(int));
					memcpy(&peer_gateway, ((char*)&packet.data) + (sizeof(int) * 2), sizeof(int));
					memcpy(&peer_mtu,     ((char*)&packet.data) + (sizeof(int) * 3), sizeof(int));

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
						console_log("Setting Routes");
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

					peer->state       = CONNECTED;
					peer->internal_ip = peer_ip;
					peer->addr        = addr;
					peer->tx          = 0;
					peer->rx          = 0;
					peer->quota       = 5497558138880;

					update_ping(peer);

					peer->session = packet_session;

					console_log("Assigned IP [%s] Subnet [%s] Via Gateway [%s]", set_ip, set_subnet, set_gateway);
					printf("\e[1;1H\e[2J");
				}
			} else if(packet_type == CONNECT_REQUEST && !is_client) {
				char token[20];
				int timestamp = time(NULL);
				char temp[strlen(server_token) + sizeof(int)];
				memcpy(temp, server_token, strlen(server_token));
				memcpy(temp + strlen(server_token), &timestamp, sizeof(int));
				SHA1(token, temp, sizeof(temp));

				if(memcmp((char*)&packet.data, token, sizeof(token)) == 0) {
					Peer *peer        = get_disconnected_peer(peers);
					uint32_t alloc_ip = get_peer_free_ip(peers);
					if(peer && alloc_ip != 0) {
						memset(&packet, 0, sizeof(Packet));
						packet.header.type = htonl(MSG);
						strcpy((char*)&(packet.data), "Authenticated");
						send_peer(socket, rand(), (char*)&packet, sizeof(Packet), &addr, RELIABLE);

						peer->state        = CONNECTED;
						peer->internal_ip  = alloc_ip;
						peer->addr         = addr;
						peer->tx           = 0;
						peer->rx           = 0;
						peer->quota        = 5497558138880;

						update_ping(peer);

						fill_random((char*)&peer->session, sizeof(Session));

						memset(&packet, 0, sizeof(Packet));
						packet.header.type	   = htonl(CONNECT_RESPONSE);
						packet.header.size	   = htonl(0);
						int tun_ip			   = htonl(alloc_ip);
						int tun_subnet		   = htonl(inet_addr("255.255.255.0"));
						int tun_gateway		   = htonl(inet_addr("10.0.0.1"));
						int mtu				   = htonl(MAX_MTU);
						memcpy(((char*)&packet.data) + (sizeof(int) * 0), &tun_ip,      sizeof(int));
						memcpy(((char*)&packet.data) + (sizeof(int) * 1), &tun_subnet,  sizeof(int));
						memcpy(((char*)&packet.data) + (sizeof(int) * 2), &tun_gateway, sizeof(int));
						memcpy(((char*)&packet.data) + (sizeof(int) * 3), &mtu,         sizeof(int));
						packet.header.session = peer->session;
						send_peer(socket, rand(), (char*)&packet, sizeof(Packet), &peer->addr, RELIABLE);
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
			} else if(packet_type == DATA) {
				if(peer && (peer->tx + peer->rx) < peer->quota) {
					IPPacket *ip_hdr = (IPPacket*)&packet.data;
					if(
						((ip_hdr->dst_addr == peer->internal_ip && is_client) || 
						(ip_hdr->src_addr == peer->internal_ip && !is_client)) && 
						packet_size <= (MAX_MTU)
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
			} else if(packet_type == LOGIN_FAILED && is_client) {
				warning("Login Failed, Reconnecting...");
				sleep(1);
				connect_server(socket, addr, server_token);
			} else if(packet_type == CONNECTION_REJECTED && is_client) {
				warning("Connection Failed, Connection Rejected. Reconnecting...");
				sleep(1);
				connect_server(socket, addr, server_token);
			} else if(packet_type == MSG && is_client) {
				*(((char*)&(packet.data)) + sizeof(PacketData)) = '\0';
				console_log("[Server] %s", (char*)&(packet.data));
			}
		}

		if(FD_ISSET(tun->fd, &rdset)) {
			memset(&packet, 0, sizeof(Packet));
			int size = read(tun->fd, (char*)&packet.data, sizeof(PacketData));

			IPPacket *ip_hdr = (IPPacket*)&packet.data;

			Peer *peer = NULL;
			if(is_client) {
				peer = get_peer_by_ip(peers, ip_hdr->src_addr);
			} else {
				peer = get_peer_by_ip(peers, ip_hdr->dst_addr);
			}
			if(peer && (peer->tx + peer->rx) < peer->quota) {
				tx += size;
				peer->tx += size;

				packet.header.type    = htonl(DATA);
				packet.header.size    = htonl(size);
				packet.header.session = peer->session;
				send_peer(socket, rand(), (char*)&packet, sizeof(PacketHeader) + size, &peer->addr, DATAGRAM);
			}
		}
	}
}

void fill_random(char *buffer, int size) {
	for(int i = 0; i < size; i++) {
		*(buffer + i) = (char)random();
	}
}

void stop_core() {
	exit(0);
}
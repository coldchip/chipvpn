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
#include "chipvpn.h"

void init_client() {
	if (signal(SIGINT, stop_client) == SIG_ERR) {
		error("Unable to Setup Signal Handlers");
	}

	srand((unsigned) time(NULL));

	Tun *tun = open_tun("");
	if(tun < 0 || tun  == NULL) {
		error("VPN Socket Creation Failed, Run as Sudo");
	}

	while(1) {
		run_client(tun);
		sleep(1);
	}
}

void run_client(Tun *tun) {

	FILE *fp = fopen("client.conf", "rb");

	char *server_ip          = read_string(fp, "server");
	char *server_port        = read_string(fp, "port");
	char *server_token       = read_string(fp, "token");
	bool  server_pull_routes = read_bool(fp, "pull_routes");

	if(!server_ip || !server_port) {
		error("Server ip or port is not defined in the config");
	}
	if(!server_token) {
		error("Token is not defined");
	}

	fclose(fp);

	int sock = socket(AF_INET, SOCK_DGRAM, 0);

	struct sockaddr_in     addr;
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = inet_addr(server_ip); 
	addr.sin_port        = htons(atoi(server_port));

	Socket socket;
	socket.fd = sock;
	list_clear(&socket.defrag_queue);
	list_clear(&socket.tx_queue);

	Peers *peers = new_peer_container(1);

	int last_ping  = 0;

	uint64_t tx = 0;
	uint64_t rx = 0;

	fd_set rdset;

	struct timeval tv;

	console_log("Connecting... ");

	Packet packet;
	packet.header.type = htonl(CONNECT);
	packet.header.size = htonl(0);
	strcpy((char*)&packet.data, server_token);
	
	send_peer(&socket, rand(), (char*)&packet, sizeof(Packet), &addr, RELIABLE);

	while(1) {
		tv.tv_sec  = PING_INTERVAL;
		tv.tv_usec = 0;

		FD_ZERO(&rdset);
		FD_SET(tun->fd, &rdset);
		FD_SET(sock, &rdset);

		select(max(tun->fd, sock) + 1, &rdset, NULL, NULL, &tv);

		if((time(NULL) - last_ping) >= PING_INTERVAL) {
			socket_service(&socket);
			for(Peer *peer = peers->peers; peer < &peers->peers[peers->peerCount]; ++peer) {
				if(is_connected(peer)) {
					memset(&packet, 0, sizeof(Packet));
					packet.header.type = htonl(PING);
					packet.header.size = htonl(0);
					memcpy(packet.header.session, peer->session, sizeof(packet.header.session));
					send_peer(&socket, rand(), (char*)&packet, sizeof(PacketHeader), &peer->addr, RELIABLE);
					
					if(is_unpinged(peer)) {
						close(sock);
						peer->state = DISCONNECTED;
						printf("\n");
						warning("No Ping Received, Reconnecting to Server");
						free_peer_container(peers);
						return;
					}
					printf("\r[%lld] Byte(s) Received [%lld] Byte(s) Sent", (long long)rx, (long long)tx);
				}
			}
			last_ping = time(NULL);
		}

		if(FD_ISSET(sock, &rdset)) {
			memset(&packet, 0, sizeof(Packet));
			if(!recv_peer(&socket, (char*)&packet, sizeof(Packet), &addr)) {
				continue;
			}

			int   packet_type    = ntohl(packet.header.type);
			int   packet_size    = ntohl(packet.header.size);
			char *packet_session = (char*)&(packet.header.session);

			Peer *peer = get_peer_by_session(peers, packet_session);
			if(peer) {
				// Update peer address
				peer->addr = addr;
			}

			switch(packet_type) {
				case CONNECT: 
				{
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

						memcpy(peer->session, packet_session, sizeof(packet.header.session));

						console_log("Assigned IP [%s] Subnet [%s] Via Gateway [%s]", set_ip, set_subnet, set_gateway);
					}
				}
				break;
				case DATA:
				{
					if(peer && (peer->tx + peer->rx) < peer->quota) {
						IPPacket *ippacket = (IPPacket*)&packet.data;
						if(ippacket->dst_addr == peer->internal_ip && packet_size <= (MAX_MTU)) {
							// Check if source is same as peer(Prevents IP spoofing) and bound packet to mtu size
							rx += packet_size;
							peer->rx += packet_size;

							if(write(tun->fd, (char*)&(packet.data), packet_size)) {}
						}
					}
				}
				break;
				case PING:
				{
					if(peer) {
						update_ping(peer);
					}
				}
				break;
				case LOGIN_FAILED:
				{
					error("Login Failed, Disconnected");
				}
				break;
				case CONNECTION_REJECTED:
				{
					warning("Connection Failed, Connection Rejected. Reconnecting");
					free_peer_container(peers);
					return;
				}
				break;
			}
		}

		if(FD_ISSET(tun->fd, &rdset)) {
			memset(&packet, 0, sizeof(Packet));
			int size = read(tun->fd, (char*)&packet.data, sizeof(PacketData));

			IPPacket *ippacket = (IPPacket*)&packet.data;

			Peer *peer = get_peer_by_ip(peers, ippacket->src_addr);

			if(peer && (peer->tx + peer->rx) < peer->quota) {
				tx += size;
				peer->tx += size;

				packet.header.type = htonl(DATA);
				packet.header.size = htonl(size);
				memcpy(packet.header.session, peer->session, sizeof(packet.header.session));
				send_peer(&socket, rand(), (char*)&packet, sizeof(PacketHeader) + size, &peer->addr, DATAGRAM);
			}
		}
	}
}

void stop_client() {
	exit(0);
}
#include <stdio.h>
#include <time.h>
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

void init_server() {
	if(signal(SIGINT, stop_server) == SIG_ERR && signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		error("Unable to Setup Signal Handlers");
	}

	srand((unsigned) time(NULL));

	Tun *tun = open_tun("");
	if(tun < 0 || tun  == NULL) {
		error("VPN Socket Creation Failed, Run as Sudo");
	}
	setifip(tun, "10.0.0.1", "255.255.255.0", MAX_MTU);
	ifup(tun);

	run_server(tun);
}

void run_server(Tun *tun) {

	FILE *fp = fopen("server.conf", "rb");

	char *server_ip        = read_string(fp, "server");
	char *server_port      = read_string(fp, "port");
	char *server_token     = read_string(fp, "token");
	int   server_max_peers = read_int(fp, "max_peers");

	if(!server_ip || !server_port) {
		error("Server ip or port is not defined in the config");
	}
	if(!server_token) {
		error("Token is not defined");
	}

	fclose(fp);

	int sock = socket(AF_INET, SOCK_DGRAM, 0);

	struct sockaddr_in      baddr;
	baddr.sin_family      = AF_INET;
    baddr.sin_addr.s_addr = inet_addr(server_ip); 
    baddr.sin_port        = htons(atoi(server_port));

	if(bind(sock, (struct sockaddr *)&baddr, sizeof(baddr)) < 0) { 
		error("Bind Failed");
	}

	struct sockaddr_in addr;

	Socket socket;
	socket.fd = sock;
	list_clear(&socket.defrag_queue);
	list_clear(&socket.tx_queue);

	Peers *peers = new_peer_container(server_max_peers);

	uint64_t tx = 0;
	uint64_t rx = 0;

	Packet packet;

	int last_ping = 0;

	fd_set rdset;

	struct timeval tv;

	while(1) {
		tv.tv_sec  = PING_INTERVAL;
		tv.tv_usec = 0;

		FD_ZERO(&rdset);
		FD_SET(tun->fd, &rdset);
		FD_SET(sock, &rdset);

		select(max(tun->fd, sock) + 1, &rdset, NULL, NULL, &tv);

		if((time(NULL) - last_ping) >= PING_INTERVAL) {
			socket_service(&socket);
			int i = 0;
			for(Peer *peer = peers->peers; peer < &peers->peers[peers->peerCount]; ++peer) {
				if(is_connected(peer)) {
					i++;
					memset(&packet, 0, sizeof(Packet));
					packet.header.type = htonl(PING);
					packet.header.size = htonl(0);
					memcpy(packet.header.session, peer->session, sizeof(packet.header.session));
					send_peer(&socket, rand(), (char*)&packet, sizeof(PacketHeader), &peer->addr, RELIABLE);
					
					if(is_unpinged(peer)) {
						peer->state = DISCONNECTED;
					}
				}
			}
			last_ping = time(NULL);
			printf("\r[%i/%i] Peer(s) Connected. [%lld] Byte(s) Received [%lld] Byte(s) Sent", i, server_max_peers, (long long)rx, (long long)tx);
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
					if(strcmp(server_token, (char*)&packet.data) == 0) {
						Peer *peer         = get_disconnected_peer(peers);
						uint32_t alloc_ip  = get_peer_free_ip(peers);
						if(peer && alloc_ip != 0) {
							peer->state        = CONNECTED;
							peer->internal_ip  = alloc_ip;
							peer->addr         = addr;
							peer->tx           = 0;
							peer->rx           = 0;
							peer->quota        = 5497558138880;

							update_ping(peer);

							fill_random(peer->session, sizeof(packet.header.session));

							memset(&packet, 0, sizeof(Packet));
							packet.header.type	   = htonl(CONNECT);
							packet.header.size	   = htonl(0);
							int tun_ip			   = htonl(alloc_ip);
							int tun_subnet		   = htonl(inet_addr("255.255.255.0"));
							int tun_gateway		   = htonl(inet_addr("10.0.0.1"));
							int mtu				   = htonl(MAX_MTU);
							memcpy(((char*)&packet.data) + (sizeof(int) * 0), &tun_ip,      sizeof(int));
							memcpy(((char*)&packet.data) + (sizeof(int) * 1), &tun_subnet,  sizeof(int));
							memcpy(((char*)&packet.data) + (sizeof(int) * 2), &tun_gateway, sizeof(int));
							memcpy(((char*)&packet.data) + (sizeof(int) * 3), &mtu,         sizeof(int));
							memcpy(packet.header.session, peer->session, sizeof(packet.header.session));
							send_peer(&socket, rand(), (char*)&packet, sizeof(Packet), &peer->addr, RELIABLE);
						} else {
							memset(&packet, 0, sizeof(Packet));
							packet.header.type = htonl(CONNECTION_REJECTED);
							send_peer(&socket, rand(), (char*)&packet, sizeof(Packet), &addr, RELIABLE);
						}
					} else {
						memset(&packet, 0, sizeof(Packet));
						packet.header.type = htonl(LOGIN_FAILED);
						send_peer(&socket, rand(), (char*)&packet, sizeof(Packet), &addr, RELIABLE);
					}
				}
				break;
				case DATA:
				{
					if(peer && (peer->tx + peer->rx) < peer->quota) {
						IPPacket *ippacket = (IPPacket*)&packet.data;
						if(ippacket->ip_src.s_addr == peer->internal_ip && packet_size <= (MAX_MTU)) {
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
					
				}
				break;
				case CONNECTION_REJECTED:
				{

				}
				break;
			}
		}

		if(FD_ISSET(tun->fd, &rdset)) {
			memset(&packet, 0, sizeof(Packet));
			int size = read(tun->fd, (char*)&packet.data, sizeof(PacketData));

			IPPacket *ippacket = (IPPacket*)&packet.data;

			Peer *peer = get_peer_by_ip(peers, ippacket->ip_dst.s_addr);

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

void fill_random(char *buffer, int size) {
	for(int i = 0; i < size; i++) {
		*(buffer + i) = (char)random();
	}
}

void stop_server() {
	exit(0);
}
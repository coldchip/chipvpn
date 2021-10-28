#include <arpa/inet.h>
#include "packet.h"

int vpnpacket_len(VPNPacket *packet) {
	return ntohl(packet->header.size);
}

int vpnpacket_type(VPNPacket *packet) {
	return ntohl(packet->header.type);
}
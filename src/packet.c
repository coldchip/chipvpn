#include <arpa/inet.h>
#include "packet.h"

int vpnpacket_len(VPNPacket *packet) {
	return ntohs(packet->header.size);
}

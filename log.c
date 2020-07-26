#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "chipvpn.h"

LOG *log_init() {
	LOG *log = malloc(sizeof(LOG));
	log->fp = fopen("vpn.log", "w+");
	return log;
}

void log_packet(LOG *log, IPPacket *packet) {
	char ip_src[16];
	sprintf(ip_src, "%i.%i.%i.%i", ((packet->src_addr) >> 0) & 0xFF, ((packet->src_addr) >> 8) & 0xFF, ((packet->src_addr) >> 16) & 0xFF, ((packet->src_addr) >> 24) & 0xFF);
	
	char ip_dst[16];
	sprintf(ip_dst, "%i.%i.%i.%i", ((packet->dst_addr) >> 0) & 0xFF, ((packet->dst_addr) >> 8) & 0xFF, ((packet->dst_addr) >> 16) & 0xFF, ((packet->dst_addr) >> 24) & 0xFF);
					
	char protocol[32];
	strcpy(protocol, "Unknown");

	switch(packet->ip_p) {
		case 6: {
			strcpy(protocol, "TCP");
		}
		break;
		case 17: {
			strcpy(protocol, "UDP");
		}
		break;
	}
	if(ftell(log->fp) > (1024 * 1024) * 20) {
		fflush(log->fp);
		log->fp = freopen(NULL, "w+", log->fp);
	}
	fprintf(log->fp, "S: %s D: %s P: %s\n", ip_src, ip_dst, protocol);
}

void log_free(LOG *log) {
	fclose(log->fp);
	free(log);
}
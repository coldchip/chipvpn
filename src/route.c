#include "route.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <net/route.h>
#include <sys/socket.h>
#include <arpa/inet.h>

VPNRoute *chipvpn_route_create() {
	VPNRoute *route = malloc(sizeof(VPNRoute));
	return route;
}

void chipvpn_route_add(struct in_addr src, struct in_addr mask, struct in_addr dst, char *dev) {
    int fd = socket( PF_INET, SOCK_DGRAM,  IPPROTO_IP);

    struct rtentry route;
    memset(&route, 0, sizeof(route));

    struct sockaddr_in *addr = (struct sockaddr_in*) &route.rt_dst;
	addr->sin_family = AF_INET;
	addr->sin_addr = src;

	addr = (struct sockaddr_in*) &route.rt_genmask;
	addr->sin_family = AF_INET;
	addr->sin_addr = mask;

	addr = (struct sockaddr_in*)&route.rt_gateway;
	addr->sin_family = AF_INET;
	addr->sin_addr = dst;

	route.rt_dev = dev;
	route.rt_flags = RTF_UP | RTF_GATEWAY;
    route.rt_metric = 0;

    char src_c[24];
    char mask_c[24];
    char dst_c[24];
	strcpy(src_c, inet_ntoa(src));
	strcpy(mask_c, inet_ntoa(mask));
	strcpy(dst_c, inet_ntoa(dst));

    printf("ip %s mask %s to %s\n", src_c, mask_c, dst_c);

    if(ioctl(fd, SIOCADDRT, &route) < 0) {
        printf("ioctl failed and returned errno %s \n", strerror(errno));
    }
    close(fd);
}

void chipvpn_route_free(VPNRoute *route) {
	free(route);
}
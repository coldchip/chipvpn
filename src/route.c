#include "route.h"
#include "chipvpn.h"
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

VPNRoute *chipvpn_route_new(struct in_addr src, struct in_addr mask, struct in_addr dst, char *dev) {
	VPNRoute *route = malloc(sizeof(VPNRoute));

	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	memset(&route->entry, 0, sizeof(route->entry));

	struct sockaddr_in *addr = (struct sockaddr_in*)&(route->entry.rt_dst);
	addr->sin_family = AF_INET;
	addr->sin_addr = src;

	addr = (struct sockaddr_in*)&(route->entry.rt_genmask);
	addr->sin_family = AF_INET;
	addr->sin_addr = mask;

	addr = (struct sockaddr_in*)&(route->entry.rt_gateway);
	addr->sin_family = AF_INET;
	addr->sin_addr = dst;

	route->entry.rt_dev = chipvpn_strdup(dev);
	route->entry.rt_flags = RTF_UP | RTF_GATEWAY;
	route->entry.rt_metric = 0;

	char src_c[INET_ADDRSTRLEN];
	char mask_c[INET_ADDRSTRLEN];
	char dst_c[INET_ADDRSTRLEN];
	strcpy(src_c, inet_ntoa(src));
	strcpy(mask_c, inet_ntoa(mask));
	strcpy(dst_c, inet_ntoa(dst));

	chipvpn_log("add route ip [%s] mask [%s] via [%s]", src_c, mask_c, dst_c);

	if(ioctl(fd, SIOCADDRT, &route->entry) < 0) {
		chipvpn_warn("route set failed due to: %s", strerror(errno));
	}
	close(fd);

	return route;
}

void chipvpn_route_add(List *list, struct in_addr src, struct in_addr mask, struct in_addr dst, char *dev) {
	VPNRoute *route = chipvpn_route_new(src, mask, dst, dev);
	list_insert(list_end(list), route);
}

void chipvpn_route_free(VPNRoute *route) {
	char src_c[INET_ADDRSTRLEN];
	char mask_c[INET_ADDRSTRLEN];
	char dst_c[INET_ADDRSTRLEN];

	strcpy(src_c, inet_ntoa(((struct sockaddr_in*)&route->entry.rt_dst)->sin_addr));
	strcpy(mask_c, inet_ntoa(((struct sockaddr_in*)&route->entry.rt_genmask)->sin_addr));
	strcpy(dst_c, inet_ntoa(((struct sockaddr_in*)&route->entry.rt_gateway)->sin_addr));

	chipvpn_log("del route ip [%s] mask [%s] via [%s]", src_c, mask_c, dst_c);

	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	if(ioctl(fd, SIOCDELRT, &route->entry) < 0) {
		chipvpn_warn("route del failed due to: %s", strerror(errno));
	}
	close(fd);

	free(route->entry.rt_dev);
	free(route);
}
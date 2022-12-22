#ifndef ROUTE_H
#define ROUTE_H

#include "list.h"
#include <netinet/in.h>
#include <net/route.h>

typedef struct _VPNRoute {
	ListNode node;
	struct rtentry entry;
} VPNRoute;

VPNRoute *chipvpn_route_new(struct in_addr src, struct in_addr mask, struct in_addr dst, char *dev);
void chipvpn_route_add(List *list, struct in_addr src, struct in_addr mask, struct in_addr dst, char *dev);
void chipvpn_route_free(VPNRoute *route);

#endif
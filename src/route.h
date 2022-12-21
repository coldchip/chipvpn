#ifndef ROUTE_H
#define ROUTE_H

#include "list.h"
#include <netinet/in.h>

typedef struct _VPNRoute {
	List routes;
} VPNRoute;

VPNRoute *chipvpn_route_create();
void chipvpn_route_add(struct in_addr src, struct in_addr mask, struct in_addr dst, char *dev);
void chipvpn_route_free(VPNRoute *route);

#endif
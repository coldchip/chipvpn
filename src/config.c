/*
 * ColdChip ChipVPN
 *
 * Copyright (c) 2016-2021, Ryan Loh <ryan@chip.sg>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README for more details.
 */

#include "config.h"
#include "chipvpn.h"
#include "list.h"
#include "cJSON.h"
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>

VPNConfig *chipvpn_config_create() {
	VPNConfig *config = malloc(sizeof(VPNConfig));
	return config;
}

bool chipvpn_config_load(VPNConfig *config, const char *config_file) {
	list_clear(&config->push_routes);

	char *buf = chipvpn_read_file(config_file);
	if(!buf) {
		return false;
	}

	cJSON *json = cJSON_Parse(buf);
	if(!json) {
		return false;
	}
	cJSON *cjson_connect     = cJSON_GetObjectItem(json, "connect");
	cJSON *cjson_bind        = cJSON_GetObjectItem(json, "bind");
	cJSON *cjson_port        = cJSON_GetObjectItem(json, "port");
	cJSON *cjson_token       = cJSON_GetObjectItem(json, "token");
	cJSON *cjson_pull_routes = cJSON_GetObjectItem(json, "pull_routes");
	cJSON *cjson_push_routes = cJSON_GetObjectItem(json, "push_routes");
	cJSON *cjson_max_peers   = cJSON_GetObjectItem(json, "max_peers");
	cJSON *cjson_gateway     = cJSON_GetObjectItem(json, "gateway");
	cJSON *cjson_subnet      = cJSON_GetObjectItem(json, "subnet");
	cJSON *cjson_mtu         = cJSON_GetObjectItem(json, "mtu");
	cJSON *cjson_sendbuf     = cJSON_GetObjectItem(json, "sendbuf");
	cJSON *cjson_recvbuf     = cJSON_GetObjectItem(json, "recvbuf");
	cJSON *cjson_qlen        = cJSON_GetObjectItem(json, "txqueuelen");

	chipvpn_config_reset(config);

	if(cjson_connect && cJSON_IsString(cjson_connect)) {
		config->mode = MODE_CLIENT;
		strcpy(config->ip, cjson_connect->valuestring);
	}
	if(cjson_bind && cJSON_IsString(cjson_bind)) {
		config->mode = MODE_SERVER;
		strcpy(config->ip, cjson_bind->valuestring);
	}
	if(cjson_port && cJSON_IsNumber(cjson_port)) {
		config->port = cjson_port->valueint;
	}
	if(cjson_token && cJSON_IsString(cjson_token)) {
		strcpy(config->token, cjson_token->valuestring);
	}
	if(cjson_pull_routes && cJSON_IsBool(cjson_pull_routes) && cJSON_IsTrue(cjson_pull_routes)) {
		config->pull_routes = true;
	}
	if(cjson_push_routes && cJSON_IsArray(cjson_push_routes)) {
		cJSON *cjson_route;
		cJSON_ArrayForEach(cjson_route, cjson_push_routes) {
    		cJSON *cjson_route_src  = cJSON_GetObjectItem(cjson_route, "src");
			cJSON *cjson_route_mask = cJSON_GetObjectItem(cjson_route, "mask");

			if(
				(cjson_route_src && cJSON_IsString(cjson_route_src)) && 
				(cjson_route_mask && cJSON_IsString(cjson_route_mask))
			) {
				struct in_addr src, mask;
				src.s_addr = inet_addr(cjson_route_src->valuestring);
				mask.s_addr = inet_addr(cjson_route_mask->valuestring);

				VPNConfigRoute *route = malloc(sizeof(VPNConfigRoute));
				route->src  = src;
				route->mask = mask;

				list_insert(list_end(&config->push_routes), route);
			}
    	}
	}
	if(cjson_max_peers && cJSON_IsNumber(cjson_max_peers) && cjson_max_peers->valueint > 0) {
		config->max_peers = cjson_max_peers->valueint;
	}
	if(cjson_gateway && cJSON_IsString(cjson_gateway)) {
		strcpy(config->gateway, cjson_gateway->valuestring);
	}
	if(cjson_subnet && cJSON_IsString(cjson_subnet)) {
		strcpy(config->subnet, cjson_subnet->valuestring);
	}
	if(cjson_mtu && cJSON_IsNumber(cjson_mtu)) {
		config->mtu = cjson_mtu->valueint;
	}
	if(cjson_sendbuf && cJSON_IsNumber(cjson_sendbuf)) {
		config->sendbuf = cjson_sendbuf->valueint;
	}
	if(cjson_recvbuf && cJSON_IsNumber(cjson_recvbuf)) {
		config->recvbuf = cjson_recvbuf->valueint;
	}
	if(cjson_qlen && cJSON_IsNumber(cjson_qlen)) {
		config->qlen = cjson_qlen->valueint;
	}

	free(buf);
	cJSON_Delete(json);

	return true;
}

void chipvpn_config_reset(VPNConfig *config) {
	config->mode = MODE_SERVER;
	strcpy(config->ip, "0.0.0.0");
	config->port = 443;
	strcpy(config->token, "abcdef");
	config->pull_routes = false;
	list_clear(&config->push_routes);
	config->max_peers = 8;
	strcpy(config->gateway, "10.9.8.1");
	strcpy(config->subnet, "255.255.255.0");
	config->mtu = 1500;
	config->sendbuf = 256000;
	config->recvbuf = 256000;
	config->qlen = 1000;
}

void chipvpn_config_free(VPNConfig *config) {
	while(!list_empty(&config->push_routes)) {
		VPNConfigRoute *route = (VPNConfigRoute*)list_remove(list_begin(&config->push_routes));
		free(route);
	}
	free(config);
}
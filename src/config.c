/*
 * ColdChip ChipVPN
 *
 * Copyright (c) 2016-2021, Ryan Loh <ryan@coldchip.ru>
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
#include "cJSON.h"
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

bool chipvpn_load_config(ChipVPNConfig *config, const char *config_file) {
	char *buf = read_file_into_buffer(config_file);
	if(!buf) {
		return false;
	}

	cJSON *json = cJSON_Parse(buf);
	if(!json) {
		return false;
	}
	cJSON *cjson_connect         = cJSON_GetObjectItem(json, "connect");
	cJSON *cjson_bind            = cJSON_GetObjectItem(json, "bind");
	cJSON *cjson_port            = cJSON_GetObjectItem(json, "port");
	cJSON *cjson_token           = cJSON_GetObjectItem(json, "token");
	cJSON *cjson_pull_routes     = cJSON_GetObjectItem(json, "pull_routes");
	cJSON *cjson_push_routes     = cJSON_GetObjectItem(json, "push_routes");
	cJSON *cjson_max_peers       = cJSON_GetObjectItem(json, "max_peers");
	cJSON *cjson_gateway         = cJSON_GetObjectItem(json, "gateway");
	cJSON *cjson_subnet          = cJSON_GetObjectItem(json, "subnet");
	cJSON *cjson_plugin          = cJSON_GetObjectItem(json, "plugin");

	chipvpn_load_default_config(config);

	if(cjson_connect && cJSON_IsString(cjson_connect)) {
		config->mode = MODE_CLIENT;
		strcpy(config->ip, cjson_connect->valuestring);
	}
	if(cjson_bind && cJSON_IsString(cjson_bind)) {
		config->mode = MODE_SERVER;
		strcpy(config->ip, cjson_bind->valuestring);
	}
	if((cjson_port && cJSON_IsNumber(cjson_port))) {
		config->port = cjson_port->valueint;
	}
	if((cjson_token && cJSON_IsString(cjson_token))) {
		strcpy(config->token, cjson_token->valuestring);
	}
	if(cjson_pull_routes && cJSON_IsBool(cjson_pull_routes) && cJSON_IsTrue(cjson_pull_routes)) {
		config->pull_routes = true;
	}
	if(cjson_push_routes && cJSON_IsBool(cjson_push_routes) && cJSON_IsTrue(cjson_push_routes)) {
		config->push_routes = true;
	}
	if(cjson_max_peers && cJSON_IsNumber(cjson_max_peers) && cjson_max_peers->valueint > 0) {
		config->max_peers = cjson_max_peers->valueint;
	}
	if((cjson_gateway && cJSON_IsString(cjson_gateway))) {
		strcpy(config->gateway, cjson_gateway->valuestring);
	}
	if((cjson_subnet && cJSON_IsString(cjson_subnet))) {
		strcpy(config->subnet, cjson_subnet->valuestring);
	}
	if((cjson_plugin && cJSON_IsString(cjson_plugin))) {
		strcpy(config->plugin, cjson_plugin->valuestring);
	}

	free(buf);
	cJSON_Delete(json);

	return true;
}

void chipvpn_load_default_config(ChipVPNConfig *config) {
	config->mode = MODE_SERVER;
	strcpy(config->ip, "0.0.0.0");
	config->port = 443;
	strcpy(config->token, "abcdef");
	config->pull_routes = false;
	config->push_routes = false;
	config->max_peers = 8;
	strcpy(config->gateway, "10.9.8.1");
	strcpy(config->subnet, "255.255.255.0");
	strcpy(config->plugin, "");
}
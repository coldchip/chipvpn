#include "config.h"
#include "chipvpn.h"
#include "json/include/cJSON.h"
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

ChipVPNConfig *chipvpn_load_config(char *config_file) {
	char *buf = read_file_into_buffer(config_file);

	if(!buf) {
		return NULL;
	}

	cJSON *json = cJSON_Parse(buf);
	if(!json) {
		return NULL;
	}
	cJSON *cjson_connect         = cJSON_GetObjectItem(json, "connect");
	cJSON *cjson_bind            = cJSON_GetObjectItem(json, "bind");
	cJSON *cjson_port            = cJSON_GetObjectItem(json, "port");
	cJSON *cjson_token           = cJSON_GetObjectItem(json, "token");
	cJSON *cjson_pull_routes     = cJSON_GetObjectItem(json, "pull_routes");
	cJSON *cjson_max_peers       = cJSON_GetObjectItem(json, "max_peers");
	cJSON *cjson_gateway         = cJSON_GetObjectItem(json, "gateway");
	cJSON *cjson_subnet          = cJSON_GetObjectItem(json, "subnet");

	if(
		((cjson_connect && cJSON_IsString(cjson_connect)) || 
		(cjson_bind && cJSON_IsString(cjson_bind))) && 
		(cjson_port && cJSON_IsNumber(cjson_port)) &&
		(cjson_token && cJSON_IsString(cjson_token))
	) {
		ChipVPNConfig *config = malloc(sizeof(ChipVPNConfig));
		if(cjson_connect && cJSON_IsString(cjson_connect)) {
			config->is_server = false;
			strcpy(config->ip, cjson_connect->valuestring);
		} else {
			config->is_server = true;
			strcpy(config->ip, cjson_bind->valuestring);
		}
		if(cjson_pull_routes && cJSON_IsBool(cjson_pull_routes) && cJSON_IsTrue(cjson_pull_routes)) {
			config->pull_routes = true;
		}
		if(cjson_max_peers && cJSON_IsNumber(cjson_max_peers) && cjson_max_peers->valueint > 0) {
			config->max_peers = cjson_max_peers->valueint;
		}
		if(
			(cjson_gateway && cJSON_IsString(cjson_gateway)) && 
			(cjson_subnet && cJSON_IsString(cjson_subnet))
		) {
			strcpy(config->gateway, cjson_gateway->valuestring);
			strcpy(config->subnet, cjson_subnet->valuestring);
		}

		config->port  = cjson_port->valueint;
		strcpy(config->token, cjson_token->valuestring);

		free(buf);
		cJSON_Delete(json);

		return config;
	}

	free(buf);
	cJSON_Delete(json);

	return NULL;
}

void chipvpn_free_config(ChipVPNConfig *config) {
	free(config);
}
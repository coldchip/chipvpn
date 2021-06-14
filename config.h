#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

typedef struct _ChipVPNConfig {
	char     ip[1024];
	int      port;
	char     token[1024];
	bool     is_server;
	bool     pull_routes;
	int      max_peers;
	char     gateway[32];
	char     subnet[32];
} ChipVPNConfig;

ChipVPNConfig   *chipvpn_load_config(char *config_file);
void             chipvpn_load_default_config(ChipVPNConfig *config);
void             chipvpn_free_config(ChipVPNConfig *config);

#endif
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include "chipvpn.h"

typedef struct _Tun {
	char *dev;
	int fd;
} Tun;

Tun *open_tun(char *dev);
void setifip(Tun *tun, uint32_t ip, uint32_t mask, int mtu);
void ifup(Tun *tun);
void free_tun(Tun *tun);
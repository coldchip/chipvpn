AUTOMAKE_OPTIONS = foreign
bin_PROGRAMS = chipvpn
chipvpn_SOURCES = chipvpn.c \
				cJSON_Utils.c \
				crypto.c \
				firewall.c \
				main.c \
				peer.c \
				socket.c \
				cJSON.c \
				config.c \
				event.c \
				list.c \
				packet.c \
				plugin.c \
				tun.c

chipvpn_LDADD = -lcrypto -lssl -ldl -lpthread
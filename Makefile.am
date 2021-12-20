AUTOMAKE_OPTIONS = subdir-objects foreign
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

bin_PROGRAMS = chipvpn
chipvpn_SOURCES = src/chipvpn.c \
				src/cJSON_Utils.c \
				src/crypto.c \
				src/firewall.c \
				src/main.c \
				src/peer.c \
				src/socket.c \
				src/cJSON.c \
				src/config.c \
				src/event.c \
				src/list.c \
				src/packet.c \
				src/plugin.c \
				src/tun.c

chipvpn_CFLAGS = -Ofast -s
chipvpn_LDADD = -lcrypto -lssl -ldl -lpthread

MAINTAINERCLEANFILES =                                  \
        aclocal.m4 config.guess config.xml              \
        config.h.in config.sub configure install-sh     \
        ltconfig ltmain.sh missing mkinstalldirs        \
        stamp-h.in

distclean-local:
	-(cd $(top_srcdir) && rm -rf autom4te*.cache autoscan.*)
	-(cd $(top_srcdir) && rm -rf $(PACKAGE)-*)
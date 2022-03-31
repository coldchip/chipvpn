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
				src/tun.c

chipvpn_CFLAGS = -Ofast -s -std=gnu99 -Wall
chipvpn_LDADD = -lcrypto -lssl

MAINTAINERCLEANFILES =                                  \
        aclocal.m4 config.guess config.xml              \
        config.h.in config.sub configure install-sh     \
        ltconfig ltmain.sh missing mkinstalldirs        \
        stamp-h.in

distclean-local:
	-(cd $(top_srcdir) && rm -rf autom4te*.cache autoscan.*)
	-(cd $(top_srcdir) && rm -rf $(PACKAGE)-*)

mrproper: distclean-local clean
	-(cd $(top_srcdir) && rm -rf autom4te.cache config.h config.log)
	-(cd $(top_srcdir) && rm -rf config.status libtool stamp-h1)
	-(cd $(top_srcdir) && rm -rf auxdir)
	-(cd $(top_srcdir) && rm -f configure configure.ac~)
	-(cd $(top_srcdir) && rm -f aclocal.m4 config.h.in config.h.in~)
	-(cd $(top_srcdir)/m4 && rm -f libtool.m4 ltoptions.m4)
	-(cd $(top_srcdir)/m4 && rm -f ltsugar.m4 ltversion.m4)
	-(cd $(top_srcdir)/m4 && rm -f lt~obsolete.m4)
	-find $(top_srcdir)/ -name "Makefile" -exec rm {} \;
	-find $(top_srcdir)/ -name "Makefile.in" -exec rm {} \;
	-find $(top_srcdir)/ -name ".dirstamp" -exec rm {} \;
	-find $(top_srcdir) -depth -name ".deps" -exec rm -rf {} \;
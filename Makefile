CC      := gcc
#CC      := mipsel-openwrt-linux-musl-gcc
BIN     := bin
SRCS    := $(wildcard *.c)
EXE     := $(BIN)/chipvpn
BUILDROOT := /home/ryan/openwrt-19.07.7
CFLAGS  := -Wall -Ofast -s
#CFLAGS  := -Wall -Ofast -I$(BUILDROOT)/staging_dir/target-mipsel_24kc_musl/usr/include -L$(BUILDROOT)/staging_dir/target-mipsel_24kc_musl/usr/lib -Wl,-rpath-link=$(BUILDROOT)/staging_dir/target-mipsel_24kc_musl/usr/lib 
LIBS    := -lssl -lcrypto -ldl
ifeq ($(OS),Windows_NT)
	LIBS := $(LIBS) -lws2_32
endif

.PHONY: clean install

all: $(EXE)

$(EXE): $(SRCS) | $(BIN)
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LIBS)
run:
	$(EXE)
clean:
	rm -rf bin/*
install:
	-systemctl stop chipvpn
	-mkdir -p /etc/chipvpn
	-touch /etc/chipvpn/chipvpn.json
	cp install/chipvpn.service /etc/systemd/system
	cp bin/chipvpn /usr/local/sbin
	systemctl daemon-reload
upload:
	scp -r /home/ryan/chipvpn/* ryan@coldchip.aws:/home/ryan/chipvpn
upload2:
	scp -r /home/ryan/chipvpn/* root@192.168.0.101:/root/chipvpn
upload3:
	scp -r /home/ryan/chipvpn/* ryan@192.168.0.100:/home/ryan/chipvpn
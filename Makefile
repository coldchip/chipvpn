CC      := gcc
LD      := ld
BIN     := bin
SRCS    := $(wildcard *.c)
EXE     := $(BIN)/chipvpn
CFLAGS  := -Wall -Ofast -s
LIBS    := 
ifeq ($(OS),Windows_NT)
	LIBS := $(LIBS) -lws2_32
endif

.PHONY: clean install

all: $(EXE)

$(EXE): $(SRCS) | $(BIN)
	$(CC) $(CFLAGS) $(SRCS) $(LIBS) -o $@
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
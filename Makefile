CC      := gcc
SRC     := $(wildcard *.c)
OUTPUT  := chipvpn
CFLAGS  := -Wall -Ofast -s
LIBS    := -lssl -lcrypto -ldl -lpthread

.PHONY: clean install

all: $(OUTPUT)

$(OUTPUT): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $@ $(LIBS)
run:
	$(OUTPUT)
clean:
	rm -f chipvpn
install:
	-systemctl stop chipvpn
	-mkdir -p /etc/chipvpn
	-touch /etc/chipvpn/chipvpn.json
	cp install/chipvpn.service /etc/systemd/system
	cp ./chipvpn /usr/local/sbin
	systemctl daemon-reload
upload:
	scp -r /home/ryan/chipvpn/* ryan@coldchip.aws:/home/ryan/chipvpn
upload2:
	scp -r /home/ryan/chipvpn/* root@192.168.0.101:/root/chipvpn
upload3:
	scp -r /home/ryan/chipvpn/* ryan@192.168.0.100:/home/ryan/chipvpn
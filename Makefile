COMPILER=gcc
COMPILER1=/home/ryan/openwrt/staging_dir/toolchain-mipsel_24kc_gcc-8.4.0_musl/bin/mipsel-openwrt-linux-musl-gcc
OUTPUT=build/chipvpn
OUTPUT1=build/chipvpn_router

.PHONY: install

module:
	$(COMPILER) *.c -o $(OUTPUT) -Wall -lm -g
	#$(COMPILER1) *.c -o $(OUTPUT1) -Wall -lm -lpthread -Ofast
install:
	-systemctl stop chipvpn
	-mkdir /etc/chipvpn
	-touch /etc/chipvpn/chipvpn.conf
	cp install/chipvpn.service /etc/systemd/system
	cp build/chipvpn /usr/local/sbin
	systemctl daemon-reload
upload:
	scp -r /home/ryan/chipvpn/* ryan@192.168.0.100:/home/ryan/chipvpn
upload2:
	scp -r /home/ryan/chipvpn/* ryan@116.87.77.149:/home/ryan/chipvpn

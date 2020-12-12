COMPILER=gcc
#COMPILER=/home/ryan/source-18.06.9/staging_dir/toolchain-mipsel_24kc_gcc-7.3.0_musl/bin/mipsel-openwrt-linux-gcc
OUTPUT=build/chipvpn

.PHONY: install

module:
	$(COMPILER) json/*.c chipsock/*.c *.c -o $(OUTPUT) -Wall -Ofast -s
	#$(COMPILER1) *.c -o $(OUTPUT1) -Wall -lm -lpthread -Ofast
install:
	-systemctl stop chipvpn
	-mkdir -p /etc/chipvpn
	-touch /etc/chipvpn/chipvpn.json
	cp install/chipvpn.service /etc/systemd/system
	cp build/chipvpn /usr/local/sbin
	systemctl daemon-reload
upload:
	scp -r /home/ryan/chipvpn/* ryan@34.87.165.28:/home/ryan/chipvpn
upload2:
	scp -r /home/ryan/chipvpn/* ryan@192.168.0.100:/home/ryan/chipvpn

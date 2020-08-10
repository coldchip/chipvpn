COMPILER=gcc
COMPILER1=/home/ryan/openwrt/staging_dir/toolchain-mipsel_24kc_gcc-8.4.0_musl/bin/mipsel-openwrt-linux-musl-gcc
OUTPUT=build/app
OUTPUT1=build/app_router

module:
	$(COMPILER) *.c -o $(OUTPUT) -Wall -lm -lpthread -Ofast
	$(COMPILER1) *.c -o $(OUTPUT1) -Wall -lm -lpthread -Ofast
client:
	$(OUTPUT) client
server:
	$(OUTPUT) server
upload:
	scp -r /home/ryan/chipvpn/* ryan@coldchip.ru:/home/ryan/chipvpn
upload2:
	scp -r /home/ryan/chipvpn/* ryan@192.168.0.100:/home/ryan/chipvpn
upload3:
	scp -r /home/ryan/chipvpn/* root@192.168.0.148:/root/chipvpn
upload4:
	scp -r /home/ryan/chipvpn/* root@192.168.1.100:/root/chipvpn

COMPILER=gcc
OUTPUT=build/chipvpn

.PHONY: install

module:
	$(COMPILER) json/*.c chipsock/*.c *.c -o $(OUTPUT) -Ofast
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
upload3:
	scp -r /home/ryan/chipvpn/* ryan@vpn.coldchip.ru:/home/ryan/chipvpn
upload4:
	scp -r /home/ryan/chipvpn/* root@192.168.0.148:/root/chipvpn
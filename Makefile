COMPILER=gcc
OUTPUT=build/chipvpn

.PHONY: install

module:
	$(COMPILER) *.c -o $(OUTPUT) -Wall -Ofast -s
	#$(COMPILER1) *.c -o $(OUTPUT1) -Wall -lm -lpthread -Ofast
install:
	-systemctl stop chipvpn
	-mkdir /etc/chipvpn
	-touch /etc/chipvpn/chipvpn.conf
	cp install/chipvpn.service /etc/systemd/system
	cp build/chipvpn /usr/local/sbin
	systemctl daemon-reload
upload:
	scp -r /home/ryan/chipvpn/* ryan@34.87.165.28:/home/ryan/chipvpn
upload2:
	scp -r /home/ryan/chipvpn/* ryan@192.168.0.100:/home/ryan/chipvpn

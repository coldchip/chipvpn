.PHONY: clean install

all:
	./build.sh compile
install:
	-systemctl stop chipvpn
	-mkdir -p /etc/chipvpn
	-touch /etc/chipvpn/chipvpn.json
	cp install/chipvpn.service /etc/systemd/system
	cp bin/chipvpn /usr/local/sbin
	systemctl daemon-reload
clean:
	./build.sh clean
upload:
	scp -r /home/ryan/chipvpn/* ryan@sg02.vpn.coldchip.ru:/home/ryan/chipvpn
upload2:
	scp -r /home/ryan/chipvpn/* ryan@192.168.0.100:/home/ryan/chipvpn
upload3:
	scp -r /home/ryan/chipvpn/* ryan@vpn.coldchip.ru:/home/ryan/chipvpn
upload4:
	scp -r /home/ryan/chipvpn/* root@192.168.0.148:/root/chipvpn
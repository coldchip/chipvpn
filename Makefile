COMPILER=gcc
OUTPUT=build/app

module:
	$(COMPILER) *.c -o $(OUTPUT) -Wall -lm -Ofast
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
	scp -r /home/ryan/chipvpn/* ryan@35.240.216.206:/home/ryan/chipvpn
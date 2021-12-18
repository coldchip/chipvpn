# ChipVPN - A multipeer VPN 
![logo](https://github.com/coldchip/chipvpn/raw/master/docs/chipvpn.png)

# What's so special about ChipVPN?
There are hundreds of VPN software and protocols out there, and each one are designed unique in its own way. ChipVPN is just another VPN protocol written in C and the design goal of it is to make the code very educational, readable, understandable and most importantly, easy to setup. 

# Technical aspects of ChipVPN
- Token/passphrase authentication. 
- It uses Linux TUN adapter and operates at layer 3. 
- It allows multiple clients to connect and routes the packets to the client based on the IP 
- It uses non-blocking socket with socket select. 
- The protocol uses TCP instead of UDP to bypass most firewalls. 
- It prevents changing of the IP after setting it and thus IP spoofing is not possible. 

# Prerequisites
- A machine running Linux, preferably Ubuntu 21.04
- C compiler (gcc)
- TUN/TAP kernel module

# Building from source
- `$ make`
- `$ sudo make install`

# Running it
- To run it as a server
- `sudo chipvpn server.json`
- To run it as a client
- `sudo chipvpn client.json`

# License
- Refer to `LICENSE` file. 
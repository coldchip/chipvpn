# ChipVPN - A multipeer VPN 
![logo](https://github.com/coldchip/chipvpn/raw/master/docs/chipvpn.png)

# What's so special about ChipVPN?
There are hundreds of VPN software and protocols out there, and each one are designed unique in its own way. ChipVPN is just another VPN protocol written in C and the design goal of it is to make the code very educational, readable, understandable and most importantly, easy to setup. 

# ChipVPN features
- Token/passphrase authentication. 
- AES-256 packet encryption (OpenSSL)
- Layer 3
- Uses TCP
- Non blocking
- Undetectable packets
- Multiple peers on server
- Custom plugins (in progress)

# Prerequisites
- A machine running Linux, preferably Ubuntu 21.04
- C compiler (gcc)
- TUN/TAP kernel module
- OpenSSL dev library
- pthread

# Building from source
- `$ ./configure`
- `$ make`
- `$ sudo make install`

# Running it
- To run it as a server
- `sudo chipvpn server.json`
- To run it as a client
- `sudo chipvpn client.json`

# License
- Refer to `LICENSE` file. 
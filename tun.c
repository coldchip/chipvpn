#include "tun.h"
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "packet.h"
#include "chipvpn.h"

#ifdef _WIN32
	#include <winsock2.h>
	#include <windows.h>
	#include <ws2ipdef.h>
	#include <iphlpapi.h>
	#include <netioapi.h>
	#include <stdarg.h>
	#include <stdio.h>
	#include "event.h"
	#include "wintun.h"

	static WINTUN_CREATE_ADAPTER_FUNC WintunCreateAdapter;
	static WINTUN_DELETE_ADAPTER_FUNC WintunDeleteAdapter;
	static WINTUN_DELETE_POOL_DRIVER_FUNC WintunDeletePoolDriver;
	static WINTUN_ENUM_ADAPTERS_FUNC WintunEnumAdapters;
	static WINTUN_FREE_ADAPTER_FUNC WintunFreeAdapter;
	static WINTUN_OPEN_ADAPTER_FUNC WintunOpenAdapter;
	static WINTUN_GET_ADAPTER_LUID_FUNC WintunGetAdapterLUID;
	static WINTUN_GET_ADAPTER_NAME_FUNC WintunGetAdapterName;
	static WINTUN_SET_ADAPTER_NAME_FUNC WintunSetAdapterName;
	static WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC WintunGetRunningDriverVersion;
	static WINTUN_SET_LOGGER_FUNC WintunSetLogger;
	static WINTUN_START_SESSION_FUNC WintunStartSession;
	static WINTUN_END_SESSION_FUNC WintunEndSession;
	static WINTUN_GET_READ_WAIT_EVENT_FUNC WintunGetReadWaitEvent;
	static WINTUN_RECEIVE_PACKET_FUNC WintunReceivePacket;
	static WINTUN_RELEASE_RECEIVE_PACKET_FUNC WintunReleaseReceivePacket;
	static WINTUN_ALLOCATE_SEND_PACKET_FUNC WintunAllocateSendPacket;
	static WINTUN_SEND_PACKET_FUNC WintunSendPacket;
#else
    #include <linux/if.h>
	#include <linux/if_tun.h>
	#include <sys/ioctl.h>
	#include <netinet/in.h>
#endif

#ifdef _WIN32
static HMODULE InitializeWintun(void)
{
    HMODULE Wintun =
        LoadLibrary("wintun.dll");
    if (!Wintun)
        return NULL;
	#define X(Name, Type) ((Name = (Type)GetProcAddress(Wintun, #Name)) == NULL)
    if (X(WintunCreateAdapter, WINTUN_CREATE_ADAPTER_FUNC) || X(WintunDeleteAdapter, WINTUN_DELETE_ADAPTER_FUNC) ||
        X(WintunDeletePoolDriver, WINTUN_DELETE_POOL_DRIVER_FUNC) || X(WintunEnumAdapters, WINTUN_ENUM_ADAPTERS_FUNC) ||
        X(WintunFreeAdapter, WINTUN_FREE_ADAPTER_FUNC) || X(WintunOpenAdapter, WINTUN_OPEN_ADAPTER_FUNC) ||
        X(WintunGetAdapterLUID, WINTUN_GET_ADAPTER_LUID_FUNC) ||
        X(WintunGetAdapterName, WINTUN_GET_ADAPTER_NAME_FUNC) ||
        X(WintunSetAdapterName, WINTUN_SET_ADAPTER_NAME_FUNC) ||
        X(WintunGetRunningDriverVersion, WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC) ||
        X(WintunSetLogger, WINTUN_SET_LOGGER_FUNC) || X(WintunStartSession, WINTUN_START_SESSION_FUNC) ||
        X(WintunEndSession, WINTUN_END_SESSION_FUNC) || X(WintunGetReadWaitEvent, WINTUN_GET_READ_WAIT_EVENT_FUNC) ||
        X(WintunReceivePacket, WINTUN_RECEIVE_PACKET_FUNC) ||
        X(WintunReleaseReceivePacket, WINTUN_RELEASE_RECEIVE_PACKET_FUNC) ||
        X(WintunAllocateSendPacket, WINTUN_ALLOCATE_SEND_PACKET_FUNC) || X(WintunSendPacket, WINTUN_SEND_PACKET_FUNC))
	#undef X
    {
        return NULL;
    }
    return Wintun;
}
#endif

Tun *open_tun(char *dev) {
	#ifdef _WIN32

		HMODULE wtun = InitializeWintun();
		if(!wtun) {
			return NULL;
		}

		WINTUN_ADAPTER_HANDLE Adapter = WintunOpenAdapter(L"ChipVPN", L"chipvpn");
		if(!Adapter) {
			if(!Adapter) {
		    	GUID ExampleGuid = { 0xbabedead, 0xcafe, 0xbabe, { 0x06, 0x53, 0x37, 0x99, 0x1d, 0xdf, 0xcd, 0xcf } };
				Adapter = WintunCreateAdapter(L"ChipVPN", L"chipvpn", &ExampleGuid, NULL);
				if (!Adapter) {
					return NULL;
		        }
		    }
		}

		WINTUN_SESSION_HANDLE Session = WintunStartSession(Adapter, 0x400000);
		if(!Session) {
			return NULL;
		}

		HANDLE Workers[] = {
			CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ReceivePackets, (LPVOID)Session, 0, NULL)
		};
		if (!Workers[0]) {
			return NULL;
		}

		Tun *tun = malloc(sizeof(Tun));
		tun->fd = 0;
		tun->dev = malloc(strlen(dev) + 1);
		tun->adapter = Adapter;
		tun->session = Session;
		return tun;

		#else
		struct ifreq ifr;

		char *clonedev = "/dev/net/tun";

		int fd = open(clonedev, O_RDWR);
		if(fd < 0) {
			return NULL;
		}

		memset(&ifr, 0, sizeof(ifr));

		ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

		if(strlen(dev) > IFNAMSIZ) {
			error("Interface name too long");
		}

		if(*dev) {
			strcpy(ifr.ifr_name, dev);
		}

		if(ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
			close(fd);
			return NULL;
		}

		Tun *tun = malloc(sizeof(Tun));
		tun->fd = fd;
		tun->dev = malloc(strlen(ifr.ifr_name) + 1);
		strcpy(tun->dev, ifr.ifr_name);

		return tun;
	#endif
}

void setifip(Tun* tun, uint32_t ip, uint32_t mask, int mtu) {
	#ifdef _WIN32
		MIB_UNICASTIPADDRESS_ROW AddressRow;
		InitializeUnicastIpAddressEntry(&AddressRow);
		WintunGetAdapterLUID(tun->adapter, &AddressRow.InterfaceLuid);
		AddressRow.Address.Ipv4.sin_family = AF_INET;
		AddressRow.Address.Ipv4.sin_addr.S_un.S_addr = ip; 
		AddressRow.OnLinkPrefixLength = 24; 
		DWORD LastError = CreateUnicastIpAddressEntry(&AddressRow);
		if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS) {
		
		}
	#else
		if(tun) {
			struct ifreq ifr;
			ifr.ifr_addr.sa_family = AF_INET;

			strcpy(ifr.ifr_name, tun->dev);

			struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;

			int fd = socket(AF_INET, SOCK_DGRAM, 0);

			addr->sin_addr.s_addr = ip;
			ioctl(fd, SIOCSIFADDR, &ifr);

			addr->sin_addr.s_addr = mask;
			ioctl(fd, SIOCSIFNETMASK, &ifr);

			ifr.ifr_mtu = mtu;
			ioctl(fd, SIOCSIFMTU, &ifr);

		    close(fd);
		}
	#endif
}

void ifup(Tun* tun) {
	#ifdef _WIN32
		int a = 0;
	#else
		if(tun) {
			struct ifreq ifr;
			ifr.ifr_addr.sa_family = AF_INET;

			strcpy(ifr.ifr_name, tun->dev);

			int fd = socket(AF_INET, SOCK_DGRAM, 0);

			ifr.ifr_flags |= IFF_UP;
			ioctl(fd, SIOCSIFFLAGS, &ifr);

		    close(fd);
		}
	#endif
}

#ifdef _WIN32

void ReceivePackets(_Inout_ DWORD_PTR SessionPtr) {
    WINTUN_SESSION_HANDLE Session = (WINTUN_SESSION_HANDLE)SessionPtr;
    HANDLE WaitHandles[] = { WintunGetReadWaitEvent(Session) };

    VPNDataPacket vpn_packet;

    while (true) {
        DWORD PacketSize;
        BYTE *Packet = WintunReceivePacket(Session, &PacketSize);
        if (Packet) {
        	memcpy(&vpn_packet, Packet, sizeof(vpn_packet));
        	chipvpn_tun_event(&vpn_packet, PacketSize);
            WintunReleaseReceivePacket(Session, Packet);
        }
    }
}

void SendPacket(Tun *tun, void *data, int size) {
    WINTUN_SESSION_HANDLE Session = (WINTUN_SESSION_HANDLE)tun->session;
    BYTE *Packet = WintunAllocateSendPacket(Session, size);
    if (Packet) {
        memcpy(Packet, data, size);
        WintunSendPacket(Session, Packet);
    }
}

#endif

void free_tun(Tun *tun) {
	if(tun) {
		if(tun->dev) {
			free(tun->dev);
		}
		free(tun);
	}
}
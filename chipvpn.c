#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include "chipvpn.h"

void send_peer(Socket *socket, void *data, int size, struct sockaddr_in *addr) {
	Fragment fragment;
	int pieces = floor(size / sizeof(FragmentData));
	int id     = rand();

	for(int i = 0; i <= pieces; i++) {
		int offset = i * sizeof(FragmentData);
		int frag_size  = i == pieces ? size - offset : sizeof(FragmentData);
		fragment.header.fragment = htonl(i);
		fragment.header.size     = htonl(frag_size);
		fragment.header.id       = htonl(id);
		fragment.header.max_frag = htonl(pieces);
		memcpy((char*)&fragment.data, data + offset, frag_size);

		encrypt((char*)&fragment, sizeof(Fragment));
		if(sendto(socket->fd, (char*)&fragment, sizeof(FragmentHeader) + frag_size, MSG_CONFIRM, (struct sockaddr *)addr, sizeof(struct sockaddr)) != sizeof(Fragment)) {
			//printf("send_peer error\n");
		}
	}
}

void remove_id_from_queue(List *queue, int to_remove) {
	ListNode *i = list_begin(queue);
	while(i != list_end(queue)) {
		FragmentQueue *currentQueue = (FragmentQueue*)i;
		Fragment *current = (Fragment*)&(currentQueue->packet);

		i = list_next(i);

		int id = ntohl(current->header.id);

		if(to_remove == id) {
			list_remove(&currentQueue->node);
			free(currentQueue);
		}
	}
}

bool recv_peer(Socket *socket, void *data, int size, struct sockaddr_in *addr) {
	List *defrag_queue = &socket->defrag_queue;
	int   queue_size   = 50;

	socklen_t len = sizeof(struct sockaddr);
	Fragment fragment;

	// Receive Fragment(s)
	if(recvfrom(socket->fd, (char*)&fragment, sizeof(Fragment), MSG_DONTWAIT, (struct sockaddr *)addr, &len) > 0) {
		decrypt((char*)&fragment, sizeof(Fragment));

		FragmentQueue *current_queue = malloc(sizeof(FragmentQueue));
		memcpy(&(current_queue->packet), &fragment, sizeof(Fragment));
		list_insert(list_end(defrag_queue), current_queue);
		if(list_size(defrag_queue) > queue_size) {
			FragmentQueue *current = (FragmentQueue*)list_begin(defrag_queue);
			list_remove(&current->node);
			free(current);
		}
	}

	// Fragment(s) Reassembly

	for(ListNode *i = list_begin(defrag_queue); i != list_end(defrag_queue); i = list_next(i)) {
		Fragment *head    = (Fragment*)&((FragmentQueue*)i)->packet;

		int head_frag     = ntohl(head->header.fragment);
		int head_max_frag = ntohl(head->header.max_frag);
		int head_id       = ntohl(head->header.id);
		if(head_frag == 0 && head_max_frag < queue_size) {
			int received_frag = 0;
			for(ListNode *l = list_begin(defrag_queue); l != list_end(defrag_queue); l = list_next(l)) {
				Fragment *current = (Fragment*)&((FragmentQueue*)l)->packet;

				int  frag      = ntohl(current->header.fragment);
				int  id        = ntohl(current->header.id);
				int  offset    = frag * sizeof(FragmentData);
				int  frag_size = ntohl(current->header.size);

				if((head_id == id) && offset + frag_size <= size) {
					memcpy(data + offset, (char*)&current->data, frag_size);
					if(received_frag >= head_max_frag) {
						remove_id_from_queue(defrag_queue, id);
						return true;
					}
					received_frag++;
				}
			}
		}
	}
	return false;
}

char *read_file_into_buffer(char *file) {
	FILE *infp = fopen(file, "rb");
    if (!infp) {
    	return NULL;
    }
    fseek(infp, 0, SEEK_END);
	long fsize = ftell(infp);
	char *p = malloc(fsize + 1);
	fseek(infp, 0, SEEK_SET);

	if(fread((char*)p, 1, fsize, infp)) {}

	fclose(infp);
	*(p + fsize) = '\0';

	return p;
}

char *read_string(FILE *file, char const *desired_name) { 
    char name[1024];
    char val[1024];

	memset(name, 0, sizeof(name));
	memset(val , 0, sizeof(val ));

    while (fscanf(file, "%1023[^=]=%1023[^\n]%*c", name, val) == 2) {
        if (0 == strcmp(name, desired_name)) {
            return strdup(val);
        }
    }
    return NULL;
}

bool read_bool(FILE *file, char const *desired_name) { 
    char name[1024];
    char val[1024];

	memset(name, 0, sizeof(name));
	memset(val , 0, sizeof(val ));

    while (fscanf(file, "%1023[^=]=%1023[^\n]%*c", name, val) == 2) {
        if (0 == strcmp(name, desired_name)) {
            if (0 == strcmp(val, "true")) {
            	return true;
        	}
        }
    }
    return false;
}

int read_int(FILE *file, char const *desired_name) { 
    char name[1024];
    char val[1024];

	memset(name, 0, sizeof(name));
	memset(val , 0, sizeof(val ));

    while (fscanf(file, "%1023[^=]=%1023[^\n]%*c", name, val) == 2) {
        if (0 == strcmp(name, desired_name)) {
            return atoi(val);
        }
    }
    return 0;
}

void get_default_gateway(char *ip) {
    char cmd[] = "ip route show default | awk '/default/ {print $3}'";
    FILE* fp = popen(cmd, "r");

    if(fgets(ip, 16, fp) != NULL){
        //printf("%s\n", line);
    }
    pclose(fp);
}

int exec_sprintf(char *format, ...) {
	va_list args;
    va_start(args, format);

	char fmt[1000];

	vsnprintf(fmt, sizeof(fmt), format, args);

	int res = system(fmt);
    
    va_end(args);

    return res;
}

void console_log(char *format, ...) {
	va_list args;
    va_start(args, format);

	char fmt[1000];
	#ifdef __linux
		snprintf(fmt, sizeof(fmt), "\033[0;32m[ChipVPN] %s\033[0m\n", format);
	#else
		snprintf(fmt, sizeof(fmt), "[ChipVPN] %s\n", format);
	#endif
	vprintf(fmt, args);
    
    va_end(args);
}

void warning(char *format, ...) {
	va_list args;
    va_start(args, format);

	char fmt[1000];
	#ifdef __linux
		snprintf(fmt, sizeof(fmt), "\033[0;31m[ChipVPN] %s\033[0m\n", format);
	#else
		snprintf(fmt, sizeof(fmt), "[ChipVPN] %s\n", format);
	#endif
	vprintf(fmt, args);
    
    va_end(args);
}

void error(char *format, ...) {
	va_list args;
    va_start(args, format);

	char fmt[1000];
	#ifdef __linux
		snprintf(fmt, sizeof(fmt), "\033[0;31m[ChipVPN] %s\033[0m\n", format);
	#else
		snprintf(fmt, sizeof(fmt), "[ChipVPN] %s\n", format);
	#endif
	vprintf(fmt, args);
    
    va_end(args);
	exit(1);
}
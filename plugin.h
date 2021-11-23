#ifndef PLUGIN_H
#define PLUGIN_H

#include "list.h"

typedef enum {
	QUEUE_LOGIN,
	QUEUE_LOGIN_FAILED
} QueueType;

typedef struct _PluginQueue {
	ListNode node;
	QueueType type;
	void *peer;
	char *token;

} PluginQueue;

void test(PluginQueue *queue);

typedef void (*CHIPVPN_PLUGIN_CALLBACK)(PluginQueue *queue);

#endif
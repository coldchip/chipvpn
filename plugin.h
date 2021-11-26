#ifndef PLUGIN_H
#define PLUGIN_H

#include <pthread.h>
#include "list.h"

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

List plugin_queue;

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

void chipvpn_plugin_callback(PluginQueue *queue);

typedef void (*CHIPVPN_PLUGIN_CALLBACK)(PluginQueue *queue);

#endif
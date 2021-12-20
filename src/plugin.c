#include <pthread.h>
#include "list.h"
#include "plugin.h"

void chipvpn_plugin_callback(PluginQueue *queue) {
	pthread_mutex_lock(&mutex);
	list_insert(list_end(&plugin_queue), queue);
	pthread_mutex_unlock(&mutex);
}
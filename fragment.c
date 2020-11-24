#include "chipvpn.h"
#include <stdlib.h>
#include <time.h>
#include <string.h>

FragmentQueue *new_queue(uint32_t queue_size) {
	FragmentQueue *frag_queue = malloc(sizeof(FragmentQueue));
	frag_queue->queue_size = queue_size;
	list_clear(&frag_queue->entries);
	return frag_queue;
}

FragmentEntry *new_entry(uint32_t id, char *data, uint32_t offset, uint32_t size, uint32_t count) {
	FragmentEntry *entry = malloc(sizeof(FragmentEntry));

	char *m_data = malloc(sizeof(char) * size);
	memcpy(m_data, data, size);

	entry->id   = id;
	entry->size = size;
	entry->offset = offset;
	entry->count  = count;
	entry->expiry = time(NULL) + 2;
	entry->data   = m_data;

	return entry;
}

void queue_service(FragmentQueue *queue) {
	ListNode *i = list_begin(&queue->entries);

	while(i != list_end(&queue->entries)) {
		FragmentEntry *current = (FragmentEntry*)i;
		i = list_next(i);
		if(time(NULL) > current->expiry) {
			free_entry(current);
		}
	}
}

void queue_insert(FragmentQueue *queue, uint32_t id, char *data, uint32_t offset, uint32_t size, uint32_t count) {
	FragmentEntry *entry = new_entry(id, data, offset, size, count);

	list_insert(list_end(&queue->entries), entry);

	if(list_size(&queue->entries) > queue->queue_size) {
		FragmentEntry *current = (FragmentEntry*)list_begin(&queue->entries);
		free_entry(current);
	}
}

void queue_remove(FragmentQueue *queue, uint32_t id) {
	ListNode *i = list_begin(&queue->entries);

	while(i != list_end(&queue->entries)) {
		FragmentEntry *current = (FragmentEntry*)i;
		i = list_next(i);
		if(current->id == id) {
			free_entry(current);
		}
	}
}

int queue_ready(FragmentQueue *queue, char *data, uint32_t max_size) {
	for(ListNode *i = list_begin(&queue->entries); i != list_end(&queue->entries); i = list_next(i)) {
		FragmentEntry *head_entry = (FragmentEntry*)i;
		uint32_t head_id    = head_entry->id;
		uint32_t head_count = head_entry->count;

		uint32_t counter = 0;
		uint32_t size_counter = 0;

		for(ListNode *j = list_begin(&queue->entries); j != list_end(&queue->entries); j = list_next(j)) {
			FragmentEntry *entry = (FragmentEntry*)j;
			uint32_t entry_id     = entry->id;
			uint32_t entry_offset = entry->offset;
			uint32_t entry_size   = entry->size;

			if(head_id == entry_id) {
				if(entry_offset + entry_size <= max_size) {
					counter++;
					size_counter += entry_size;
					memcpy(data + entry_offset, entry->data, entry_size);
					if(counter > head_count) {
						queue_remove(queue, head_id);
						return size_counter;
					}
				} else {
					queue_remove(queue, head_id);
					return -1;
				}
			}
		}
	}
	return -1;
}

void free_entry(FragmentEntry *entry) {
	list_remove(&entry->node);
	free(entry->data);
	free(entry);
}

void free_queue(FragmentQueue *queue) {
	List *frag_entries = &queue->entries;

	ListNode *i = list_begin(frag_entries);

	while(i != list_end(frag_entries)) {
		FragmentEntry *current = (FragmentEntry*)i;

		i = list_next(i);

		free_entry(current);
	}
	free(queue);
}
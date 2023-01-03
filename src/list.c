/*
 * Copyright (c) 2002-2020 Lee Salzman
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "list.h"
#include <stddef.h>

void list_clear(List *list) {
	list->sentinel.next = &list->sentinel;
	list->sentinel.previous = &list->sentinel;
}

ListNode * list_insert(ListNode *position, void *data) {
	ListNode *result = (ListNode *)data;

	result->previous = position->previous;
	result->next = position;

	result->previous->next = result;
	position->previous = result;

	return result;
}

void *list_remove(ListNode *position) {
	position->previous->next = position->next;
	position->next->previous = position->previous;

	return position;
}

ListNode * list_move(ListNode *position, void *dataFirst, void *dataLast) {
	ListNode *first = (ListNode *)dataFirst;
	ListNode *last = (ListNode *)dataLast;

	first->previous->next = last->next;
	last->next->previous = first->previous;

	first->previous = position->previous;
	last->next = position;

	first->previous->next = first;
	position->previous = last;

	return first;
}

size_t list_size(List *list) {
	size_t size = 0;

	for(ListNode *position = list_begin (list); position != list_end (list); position = list_next (position)) {
		++size;
	}

	return size;
}
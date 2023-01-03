/*
 * Copyright (c) 2002-2020 Lee Salzman
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef LIST_H
#define LIST_H

#include <stddef.h>

typedef struct _ListNode {
	struct _ListNode *next;
	struct _ListNode *previous;
} ListNode;

typedef struct _List {
	ListNode sentinel;
} List;

extern void list_clear(List *list);

extern ListNode *list_insert(ListNode *position, void *data);
extern void *list_remove(ListNode *position);
extern ListNode *list_move(ListNode *position, void *dataFirst, void *dataLast);

extern size_t list_size(List *list);

#define list_begin(list) ((list)->sentinel.next)
#define list_end(list) (&(list)->sentinel)

#define list_empty(list) (list_begin(list) == list_end(list))

#define list_next(iterator) ((iterator)->next)
#define list_previous(iterator) ((iterator)->previous)

#define list_front(list) ((void *) (list)->sentinel.next)
#define list_back(list) ((void *) (list)->sentinel.previous)

#endif
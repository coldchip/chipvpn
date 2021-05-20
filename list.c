#include "list.h"

void list_clear (List * list) {
   list -> sentinel.next = & list -> sentinel;
   list -> sentinel.previous = & list -> sentinel;
}

ListNode * list_insert (ListNode * position, void * data) {
   ListNode * result = (ListNode *) data;

   result -> previous = position -> previous;
   result -> next = position;

   result -> previous -> next = result;
   position -> previous = result;

   return result;
}

void *list_remove (ListNode * position) {
   position -> previous -> next = position -> next;
   position -> next -> previous = position -> previous;

   return position;
}

ListNode * list_move (ListNode * position, void * dataFirst, void * dataLast) {
   ListNode *first = (ListNode *) dataFirst;
   ListNode *last = (ListNode *) dataLast;

   first -> previous -> next = last -> next;
   last -> next -> previous = first -> previous;

   first -> previous = position -> previous;
   last -> next = position;

   first -> previous -> next = first;
   position -> previous = last;
    
   return first;
}

size_t list_size (List * list) {
   size_t size = 0;
   ListNode * position;

   for (position = list_begin (list);
        position != list_end (list);
        position = list_next (position))
     ++ size;
   
   return size;
}
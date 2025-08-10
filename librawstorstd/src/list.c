#include "rawstorstd/list.h"

#include <stddef.h>
#include <stdlib.h>

#define RAWSTOR_LIST_ITEM_TO_ITER(item) \
    ( \
        (item) != NULL ? (((void*)(item)) + sizeof(RawstorListItem)) : NULL \
    )

#define RAWSTOR_LIST_ITEM_FROM_ITER(iter) \
    (((void*)(iter)) - sizeof(RawstorListItem))


typedef struct RawstorListItem {
    struct RawstorListItem *prev;
    struct RawstorListItem *next;
} RawstorListItem;


struct RawstorList {
    size_t size;
    size_t object_size;
    RawstorListItem *head;
    RawstorListItem *tail;
};


RawstorList* rawstor_list_create(size_t object_size) {
    RawstorList *list = malloc(sizeof(RawstorList));
    if (list == NULL) {
        return NULL;
    }

    list->size = 0;
    list->object_size = object_size;
    list->head = NULL;
    list->tail = NULL;

    return list;
}


void rawstor_list_delete(RawstorList *list) {
    RawstorListItem *item = list->head;
    while (item != NULL) {
        RawstorListItem *next = item->next;
        free(item);
        item = next;
    }
    free(list);
}


void* rawstor_list_iter(RawstorList *list) {
    return RAWSTOR_LIST_ITEM_TO_ITER(list->head);
}


void* rawstor_list_next(void *iter) {
    RawstorListItem *item = RAWSTOR_LIST_ITEM_FROM_ITER(iter);
    return RAWSTOR_LIST_ITEM_TO_ITER(item->next);
}


void* rawstor_list_append(RawstorList *list) {
    RawstorListItem *item = malloc(sizeof(RawstorListItem) + list->object_size);
    if (item == NULL) {
        return NULL;
    }

    item->next = NULL;
    item->prev = NULL;

    if (list->tail != NULL) {
        list->tail->next = item;
        item->prev = list->tail;
        list->tail = item;
    } else {
        list->head = item;
        list->tail = item;
    }

    ++list->size;

    return RAWSTOR_LIST_ITEM_TO_ITER(item);
}


void* rawstor_list_remove(RawstorList *list, void *iter) {
    RawstorListItem *item = RAWSTOR_LIST_ITEM_FROM_ITER(iter);
    RawstorListItem *next = item->next;
    RawstorListItem *prev = item->prev;

    if (prev != NULL) {
        prev->next = next;
    } else {
        list->head = next;
    }

    if (next != NULL) {
        next->prev = prev;
    } else {
        list->tail = prev;
    }

    --list->size;

    free(item);

    return RAWSTOR_LIST_ITEM_TO_ITER(next);
}

int rawstor_list_empty(RawstorList *list) {
    return list->size == 0;
}


size_t rawstor_list_size(RawstorList *list) {
    return list->size;
}

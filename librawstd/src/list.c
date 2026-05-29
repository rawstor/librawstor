#include "rawstd/list.h"

#include <stddef.h>
#include <stdlib.h>

#define RAWSTD_LIST_ITEM_TO_ITER(item)                                         \
    ((item) != NULL ? (((void*)(item)) + sizeof(RawstdListItem)) : NULL)

#define RAWSTD_LIST_ITEM_FROM_ITER(iter)                                       \
    (((void*)(iter)) - sizeof(RawstdListItem))

typedef struct RawstdListItem {
    struct RawstdListItem* prev;
    struct RawstdListItem* next;
} RawstdListItem;

struct RawstdList {
    size_t size;
    size_t object_size;
    RawstdListItem* head;
    RawstdListItem* tail;
};

RawstdList* rawstd_list_create(size_t object_size) {
    RawstdList* list = malloc(sizeof(RawstdList));
    if (list == NULL) {
        return NULL;
    }

    list->size = 0;
    list->object_size = object_size;
    list->head = NULL;
    list->tail = NULL;

    return list;
}

void rawstd_list_delete(RawstdList* list) {
    RawstdListItem* item = list->head;
    while (item != NULL) {
        RawstdListItem* next = item->next;
        free(item);
        item = next;
    }
    free(list);
}

void* rawstd_list_iter(RawstdList* list) {
    return RAWSTD_LIST_ITEM_TO_ITER(list->head);
}

void* rawstd_list_next(void* iter) {
    RawstdListItem* item = RAWSTD_LIST_ITEM_FROM_ITER(iter);
    return RAWSTD_LIST_ITEM_TO_ITER(item->next);
}

void* rawstd_list_append(RawstdList* list) {
    RawstdListItem* item = malloc(sizeof(RawstdListItem) + list->object_size);
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

    return RAWSTD_LIST_ITEM_TO_ITER(item);
}

void* rawstd_list_remove(RawstdList* list, void* iter) {
    RawstdListItem* item = RAWSTD_LIST_ITEM_FROM_ITER(iter);
    RawstdListItem* next = item->next;
    RawstdListItem* prev = item->prev;

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

    return RAWSTD_LIST_ITEM_TO_ITER(next);
}

int rawstd_list_empty(RawstdList* list) {
    return list->size == 0;
}

size_t rawstd_list_size(RawstdList* list) {
    return list->size;
}

#include "list.h"

#include "utils.h"

#include <stddef.h>
#include <stdlib.h>


static int test_list_empty() {
    RawstorList *l = rawstor_list_create(sizeof(int));

    void *it = rawstor_list_iter(l);
    assertTrue(it == NULL);

    assertTrue(rawstor_list_empty(l) != 0);
    assertTrue(rawstor_list_size(l) == 0);

    rawstor_list_delete(l);

    return 0;
}


static int test_list_append() {
    int *it;
    RawstorList *l = rawstor_list_create(sizeof(int));

    it = rawstor_list_append(l);
    assertTrue(it != NULL);
    *it = 1;

    it = rawstor_list_iter(l);
    assertTrue(it != NULL);
    assertTrue(*it == 1);

    assertTrue(rawstor_list_empty(l) == 0);
    assertTrue(rawstor_list_size(l) == 1);

    rawstor_list_delete(l);

    return 0;
}


static int test_list_iter() {
    int *it;
    RawstorList *l = rawstor_list_create(sizeof(int));

    it = rawstor_list_append(l);
    assertTrue(it != NULL);
    *it = 1;

    it = rawstor_list_append(l);
    assertTrue(it != NULL);
    *it = 2;

    it = rawstor_list_append(l);
    assertTrue(it != NULL);
    *it = 3;

    it = rawstor_list_iter(l);
    assertTrue(it != NULL);
    assertTrue(*it == 1);

    it = rawstor_list_next(it);
    assertTrue(it != NULL);
    assertTrue(*it == 2);

    it = rawstor_list_next(it);
    assertTrue(it != NULL);
    assertTrue(*it == 3);

    it = rawstor_list_next(it);
    assertTrue(it == NULL);

    rawstor_list_delete(l);

    return 0;
}


static int test_list_remove() {
    int *it;
    RawstorList *l = rawstor_list_create(sizeof(int));

    it = rawstor_list_append(l);
    assertTrue(it != NULL);
    *it = 1;

    it = rawstor_list_append(l);
    assertTrue(it != NULL);
    *it = 2;

    it = rawstor_list_append(l);
    assertTrue(it != NULL);
    *it = 3;

    it = rawstor_list_iter(l);
    assertTrue(it != NULL);
    assertTrue(*it == 1);

    it = rawstor_list_next(it);
    assertTrue(it != NULL);
    assertTrue(*it == 2);

    it = rawstor_list_remove(l, it);
    assertTrue(it != NULL);
    assertTrue(*it == 3);

    it = rawstor_list_next(it);
    assertTrue(it == NULL);

    rawstor_list_delete(l);

    return 0;
}


static int test_list_remove_first() {
    int *it;
    RawstorList *l = rawstor_list_create(sizeof(int));

    it = rawstor_list_append(l);
    assertTrue(it != NULL);
    *it = 1;

    it = rawstor_list_append(l);
    assertTrue(it != NULL);
    *it = 2;

    it = rawstor_list_iter(l);
    assertTrue(it != NULL);
    assertTrue(*it == 1);

    it = rawstor_list_remove(l, it);
    assertTrue(*it == 2);

    it = rawstor_list_iter(l);
    assertTrue(it != NULL);
    assertTrue(*it == 2);

    it = rawstor_list_next(it);
    assertTrue(it == NULL);

    rawstor_list_delete(l);

    return 0;
}


static int test_list_remove_last() {
    int *it;
    RawstorList *l = rawstor_list_create(sizeof(int));

    it = rawstor_list_append(l);
    assertTrue(it != NULL);
    *it = 1;

    it = rawstor_list_append(l);
    assertTrue(it != NULL);
    *it = 2;

    it = rawstor_list_iter(l);
    assertTrue(it != NULL);
    assertTrue(*it == 1);

    it = rawstor_list_next(it);
    assertTrue(it != NULL);
    assertTrue(*it == 2);

    it = rawstor_list_remove(l, it);
    assertTrue(it == NULL);

    it = rawstor_list_iter(l);
    assertTrue(it != NULL);
    assertTrue(*it == 1);

    it = rawstor_list_next(it);
    assertTrue(it == NULL);

    rawstor_list_delete(l);

    return 0;
}


static int test_list_size() {
    int *it;
    RawstorList *l = rawstor_list_create(sizeof(int));

    assertTrue(rawstor_list_size(l) == 0);

    it = rawstor_list_append(l);
    assertTrue(it != NULL);
    *it = 1;

    assertTrue(rawstor_list_size(l) == 1);

    it = rawstor_list_append(l);
    assertTrue(it != NULL);
    *it = 2;

    assertTrue(rawstor_list_size(l) == 2);

    it = rawstor_list_append(l);
    assertTrue(it != NULL);
    *it = 3;

    assertTrue(rawstor_list_size(l) == 3);

    it = rawstor_list_iter(l);
    assertTrue(it != NULL);
    assertTrue(*it == 1);

    it = rawstor_list_next(it);
    assertTrue(it != NULL);
    assertTrue(*it == 2);

    it = rawstor_list_remove(l, it);
    assertTrue(it != NULL);
    assertTrue(*it == 3);

    assertTrue(rawstor_list_size(l) == 2);

    rawstor_list_delete(l);

    return 0;
}


int main() {
    int rval = 0;
    rval += test_list_empty();
    rval += test_list_append();
    rval += test_list_iter();
    rval += test_list_remove();
    rval += test_list_remove_first();
    rval += test_list_remove_last();
    rval += test_list_size();
    return rval ? EXIT_FAILURE : EXIT_SUCCESS;
}

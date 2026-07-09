/**
 * Copyright (C) 2025-2026, Vasily Stepanov (vasily.stepanov@gmail.com)
 *
 * SPDX-License-Identifier: LGPL-3.0
 */

#ifndef RAWSTOR_LIST_H
#define RAWSTOR_LIST_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Opaque handle to a list of strings.
 *
 * Instances of this type are created and managed internally by the library.
 * The user must never allocate or free such objects directly.
 * All strings stored in the list are immutable and are freed when the list is
 * destroyed.
 */
typedef struct RawstorStringList RawstorStringList;

/**
 * @brief Destroys the string list and frees all associated memory.
 *
 * This function releases both the list container and all strings it contains.
 * After this call, any iterators obtained from this list become invalid and
 * must not be used.
 *
 * @param list      Pointer to the list to be destroyed. May be NULL – in that
 *                  case the function does nothing.
 *
 * @warning Iterators previously obtained from this list are invalidated.
 */
void rawstor_string_list_delete(RawstorStringList* list);

/**
 * @brief Returns an iterator to the first string in the list.
 *
 * The returned iterator points to the first element of the list. The element
 * itself is a pointer to a null‑terminated string (const char*). To obtain the
 * actual string, the iterator must be dereferenced.
 *
 * @param list      Pointer to the list. Must not be NULL.
 *
 * @return          Iterator pointing to the first string, or NULL if the list
 *                  is empty.
 *
 * @note The iterator is read‑only; modifying the pointed data is not allowed.
 * @note The iterator remains valid as long as the list is not destroyed.
 *       It is not invalidated by calling any of the non‑modifying functions
 *       (empty, size, next, iter).
 *
 * @warning Passing NULL results in undefined behaviour.
 *
 * @see rawstor_string_list_next
 */
const char** rawstor_string_list_iter(RawstorStringList* list);

/**
 * @brief Advances an iterator to the next string in the list.
 *
 * Given a valid iterator previously obtained from @ref rawstor_string_list_iter
 * or from a previous call to this function, it returns an iterator to the
 * subsequent element. Dereferencing the returned iterator yields the next
 * string.
 *
 * @param iter      Current iterator. Must not be NULL.
 *
 * @return          Iterator to the next string, or NULL if the current iterator
 *                  pointed to the last element.
 *
 * @note The iterator is read‑only; modifying the pointed data is not allowed.
 * @note The returned iterator is valid only if the list has not been destroyed.
 *
 * @warning Passing NULL results in undefined behaviour.
 *
 * @see rawstor_string_list_iter
 */
const char** rawstor_string_list_next(const char** iter);

/**
 * @brief Checks whether the list is empty.
 *
 * @param list      Pointer to the list. Must not be NULL.
 *
 * @return          Non‑zero (true) if the list contains no elements, zero
 *                  (false) otherwise.
 *
 * @note This operation has O(1) complexity.
 *
 * @warning Passing NULL results in undefined behaviour.
 */
int rawstor_string_list_empty(RawstorStringList* list);

/**
 * @brief Returns the number of strings in the list.
 *
 * @param list      Pointer to the list. Must not be NULL.
 *
 * @return          Number of elements in the list.
 *
 * @note This operation has O(1) complexity.
 *
 * @warning Passing NULL results in undefined behaviour.
 */
size_t rawstor_string_list_size(RawstorStringList* list);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_LIST_H

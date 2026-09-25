#include "rawio_sync.h"

#include <rawstor/location.h>
#include <rawstor/object.h>
#include <rawstor/target.h>

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

static void set_os_error(int error) {
    errno = error;
    PyErr_SetFromErrno(PyExc_OSError);
}

typedef struct {
    PyObject_HEAD unsigned long long size;
    unsigned int width;
    unsigned long long chunk_size;
} PyObjectSpec;

// ObjectSpec is Py_TPFLAGS_BASETYPE (subclassable from Python), and a
// Python-level subclass gets its own __dict__/GC tracking added
// automatically. tp_new/tp_dealloc must therefore go through the *actual*
// type's tp_alloc/tp_free slots (which subtype_dealloc() also expects to
// have been used) rather than a fixed allocator -- PyObject_New()/
// PyObject_Free() bypass GC tracking and crash subtype_dealloc() for such
// subclasses.
static void PyObjectSpec_dealloc(PyObjectSpec* self) {
    PyTypeObject* type = Py_TYPE(self);
    freefunc free_func = (freefunc)PyType_GetSlot(type, Py_tp_free);
    free_func(self);
    Py_DECREF(type);
}

static PyObject* PyObjectSpec_new(
    PyTypeObject* type, PyObject* Py_UNUSED(args), PyObject* Py_UNUSED(kwargs)
) {
    allocfunc alloc_func = (allocfunc)PyType_GetSlot(type, Py_tp_alloc);
    PyObjectSpec* self = (PyObjectSpec*)alloc_func(type, 0);
    if (self != NULL) {
        self->size = 0;
        self->width = 0;
        self->chunk_size = 0;
    }
    return (PyObject*)self;
}

static int
PyObjectSpec_init(PyObjectSpec* self, PyObject* args, PyObject* kwargs) {
    long long size;
    unsigned int width;
    unsigned long long chunk_size = 0;
    static char* kwlist[] = {"size", "width", "chunk_size", NULL};
    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs, "LI|K", kwlist, &size, &width, &chunk_size
        )) {
        return -1;
    }
    if (size < 0) {
        PyErr_SetString(PyExc_ValueError, "size cannot be negative");
        return -1;
    }
    self->size = (unsigned long long)size;
    self->width = width;
    self->chunk_size = chunk_size;
    return 0;
}

static PyObject* PyObjectSpec_repr(PyObjectSpec* self) {
    return PyUnicode_FromFormat(
        "ObjectSpec(size=%llu, width=%u, chunk_size=%llu)", self->size,
        self->width, self->chunk_size
    );
}

static PyObject*
PyObjectSpec_get_size(PyObjectSpec* self, void* Py_UNUSED(closure)) {
    return PyLong_FromUnsignedLongLong(self->size);
}

static int PyObjectSpec_set_size(
    PyObjectSpec* self, PyObject* value, void* Py_UNUSED(closure)
) {
    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete size attribute");
        return -1;
    }

    unsigned long long new_size = PyLong_AsUnsignedLongLong(value);
    if (PyErr_Occurred()) {
        return -1;
    }
    self->size = new_size;
    return 0;
}

static PyObject*
PyObjectSpec_get_width(PyObjectSpec* self, void* Py_UNUSED(closure)) {
    return PyLong_FromUnsignedLong(self->width);
}

static int PyObjectSpec_set_width(
    PyObjectSpec* self, PyObject* value, void* Py_UNUSED(closure)
) {
    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete width attribute");
        return -1;
    }

    unsigned long new_width = PyLong_AsUnsignedLong(value);
    if (PyErr_Occurred()) {
        return -1;
    }
    self->width = (unsigned int)new_width;
    return 0;
}

static PyObject*
PyObjectSpec_get_chunk_size(PyObjectSpec* self, void* Py_UNUSED(closure)) {
    return PyLong_FromUnsignedLongLong(self->chunk_size);
}

static int PyObjectSpec_set_chunk_size(
    PyObjectSpec* self, PyObject* value, void* Py_UNUSED(closure)
) {
    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete chunk_size attribute");
        return -1;
    }

    unsigned long long new_chunk_size = PyLong_AsUnsignedLongLong(value);
    if (PyErr_Occurred()) {
        return -1;
    }
    self->chunk_size = new_chunk_size;
    return 0;
}

static PyGetSetDef PyObjectSpec_getset[] = {
    {"size", (getter)PyObjectSpec_get_size, (setter)PyObjectSpec_set_size, NULL,
     NULL},
    {"width", (getter)PyObjectSpec_get_width, (setter)PyObjectSpec_set_width,
     NULL, NULL},
    {"chunk_size", (getter)PyObjectSpec_get_chunk_size,
     (setter)PyObjectSpec_set_chunk_size, NULL, NULL},
    {NULL, NULL, NULL, NULL, NULL}
};

static PyType_Slot PyObjectSpec_slots[] = {
    {Py_tp_dealloc, (void*)PyObjectSpec_dealloc},
    {Py_tp_repr, (void*)PyObjectSpec_repr},
    {Py_tp_init, (void*)PyObjectSpec_init},
    {Py_tp_new, (void*)PyObjectSpec_new},
    {Py_tp_getset, (void*)PyObjectSpec_getset},
    {0, NULL},
};

static PyType_Spec PyObjectSpec_spec = {
    .name = "rawstor.ObjectSpec",
    .basicsize = sizeof(PyObjectSpec),
    .itemsize = 0,
    .flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .slots = PyObjectSpec_slots,
};

PyTypeObject* PyObjectSpecType = NULL;

typedef struct {
    PyObject_HEAD unsigned long long used;
    unsigned long long total;
} PyLocationInfo;

static void PyLocationInfo_dealloc(PyLocationInfo* self) {
    PyTypeObject* type = Py_TYPE(self);
    freefunc free_func = (freefunc)PyType_GetSlot(type, Py_tp_free);
    free_func(self);
    Py_DECREF(type);
}

static PyObject* PyLocationInfo_repr(PyLocationInfo* self) {
    return PyUnicode_FromFormat(
        "LocationInfo(used=%llu, total=%llu)", self->used, self->total
    );
}

static PyObject*
PyLocationInfo_get_used(PyLocationInfo* self, void* Py_UNUSED(closure)) {
    return PyLong_FromUnsignedLongLong(self->used);
}

static PyObject*
PyLocationInfo_get_total(PyLocationInfo* self, void* Py_UNUSED(closure)) {
    return PyLong_FromUnsignedLongLong(self->total);
}

static PyGetSetDef PyLocationInfo_getset[] = {
    {"used", (getter)PyLocationInfo_get_used, NULL, NULL, NULL},
    {"total", (getter)PyLocationInfo_get_total, NULL, NULL, NULL},
    {NULL, NULL, NULL, NULL, NULL}
};

static PyType_Slot PyLocationInfo_slots[] = {
    {Py_tp_dealloc, (void*)PyLocationInfo_dealloc},
    {Py_tp_repr, (void*)PyLocationInfo_repr},
    {Py_tp_getset, (void*)PyLocationInfo_getset},
    {0, NULL},
};

static PyType_Spec PyLocationInfo_spec = {
    .name = "rawstor.LocationInfo",
    .basicsize = sizeof(PyLocationInfo),
    .itemsize = 0,
    .flags = Py_TPFLAGS_DEFAULT,
    .slots = PyLocationInfo_slots,
};

PyTypeObject* PyLocationInfoType = NULL;

// The settable half of a mirror's metadata (see RawstorObjectSyncState) --
// input to Target.set_sync_state() (object_set_sync_state() below), same
// shape/pattern as ObjectSpec above (constructible, with setters) since a
// caller builds one of these and passes it in, unlike ObjectMeta/
// LocationInfo below which are output-only.
typedef struct {
    PyObject_HEAD unsigned long long epoch;
    unsigned long long sync_id;
    unsigned long long sync_id_history[RAWSTOR_OBJECT_SYNC_ID_HISTORY];
    int state;
} PyObjectSyncState;

static void PyObjectSyncState_dealloc(PyObjectSyncState* self) {
    PyTypeObject* type = Py_TYPE(self);
    freefunc free_func = (freefunc)PyType_GetSlot(type, Py_tp_free);
    free_func(self);
    Py_DECREF(type);
}

static PyObject* PyObjectSyncState_new(
    PyTypeObject* type, PyObject* Py_UNUSED(args), PyObject* Py_UNUSED(kwargs)
) {
    allocfunc alloc_func = (allocfunc)PyType_GetSlot(type, Py_tp_alloc);
    PyObjectSyncState* self = (PyObjectSyncState*)alloc_func(type, 0);
    if (self != NULL) {
        self->epoch = 0;
        self->sync_id = 0;
        for (int i = 0; i < RAWSTOR_OBJECT_SYNC_ID_HISTORY; i++) {
            self->sync_id_history[i] = 0;
        }
        self->state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN;
    }
    return (PyObject*)self;
}

// Shared by _init and the sync_id_history setter: `value` must be a
// sequence of exactly RAWSTOR_OBJECT_SYNC_ID_HISTORY integers. Written via
// PySequence_Size()/_GetItem() rather than PySequence_Fast()/
// _Fast_GET_ITEM() -- this module builds against the Limited API, which
// doesn't expose the _Fast family's macro-only accessors.
static int parse_sync_id_history(PyObject* value, unsigned long long* out) {
    Py_ssize_t n = PySequence_Size(value);
    if (n < 0) {
        return -1;
    }
    if (n != RAWSTOR_OBJECT_SYNC_ID_HISTORY) {
        PyErr_Format(
            PyExc_ValueError, "sync_id_history must have exactly %d elements",
            RAWSTOR_OBJECT_SYNC_ID_HISTORY
        );
        return -1;
    }
    for (Py_ssize_t i = 0; i < n; i++) {
        PyObject* item = PySequence_GetItem(value, i);
        if (item == NULL) {
            return -1;
        }
        unsigned long long v = PyLong_AsUnsignedLongLong(item);
        Py_DECREF(item);
        if (PyErr_Occurred()) {
            return -1;
        }
        out[i] = v;
    }
    return 0;
}

static int PyObjectSyncState_init(
    PyObjectSyncState* self, PyObject* args, PyObject* kwargs
) {
    unsigned long long epoch = 0;
    unsigned long long sync_id = 0;
    PyObject* sync_id_history_obj = NULL;
    int state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN;
    static char* kwlist[] = {
        "epoch", "sync_id", "sync_id_history", "state", NULL
    };
    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs, "|KKOi", kwlist, &epoch, &sync_id,
            &sync_id_history_obj, &state
        )) {
        return -1;
    }

    unsigned long long history[RAWSTOR_OBJECT_SYNC_ID_HISTORY] = {0};
    if (sync_id_history_obj != NULL) {
        if (parse_sync_id_history(sync_id_history_obj, history) < 0) {
            return -1;
        }
    }

    self->epoch = epoch;
    self->sync_id = sync_id;
    for (int i = 0; i < RAWSTOR_OBJECT_SYNC_ID_HISTORY; i++) {
        self->sync_id_history[i] = history[i];
    }
    self->state = state;
    return 0;
}

static PyObject* PyObjectSyncState_repr(PyObjectSyncState* self) {
    return PyUnicode_FromFormat(
        "ObjectSyncState(epoch=%llu, sync_id=%llu, state=%d)", self->epoch,
        self->sync_id, self->state
    );
}

static PyObject*
PyObjectSyncState_get_epoch(PyObjectSyncState* self, void* Py_UNUSED(closure)) {
    return PyLong_FromUnsignedLongLong(self->epoch);
}

static int PyObjectSyncState_set_epoch(
    PyObjectSyncState* self, PyObject* value, void* Py_UNUSED(closure)
) {
    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete epoch attribute");
        return -1;
    }
    unsigned long long v = PyLong_AsUnsignedLongLong(value);
    if (PyErr_Occurred()) {
        return -1;
    }
    self->epoch = v;
    return 0;
}

static PyObject* PyObjectSyncState_get_sync_id(
    PyObjectSyncState* self, void* Py_UNUSED(closure)
) {
    return PyLong_FromUnsignedLongLong(self->sync_id);
}

static int PyObjectSyncState_set_sync_id(
    PyObjectSyncState* self, PyObject* value, void* Py_UNUSED(closure)
) {
    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete sync_id attribute");
        return -1;
    }
    unsigned long long v = PyLong_AsUnsignedLongLong(value);
    if (PyErr_Occurred()) {
        return -1;
    }
    self->sync_id = v;
    return 0;
}

static PyObject* PyObjectSyncState_get_sync_id_history(
    PyObjectSyncState* self, void* Py_UNUSED(closure)
) {
    PyObject* tuple = PyTuple_New(RAWSTOR_OBJECT_SYNC_ID_HISTORY);
    if (tuple == NULL) {
        return NULL;
    }
    for (int i = 0; i < RAWSTOR_OBJECT_SYNC_ID_HISTORY; i++) {
        PyObject* v = PyLong_FromUnsignedLongLong(self->sync_id_history[i]);
        if (v == NULL) {
            Py_DECREF(tuple);
            return NULL;
        }
        PyTuple_SetItem(tuple, i, v); /* steals ref */
    }
    return tuple;
}

static int PyObjectSyncState_set_sync_id_history(
    PyObjectSyncState* self, PyObject* value, void* Py_UNUSED(closure)
) {
    if (value == NULL) {
        PyErr_SetString(
            PyExc_TypeError, "Cannot delete sync_id_history attribute"
        );
        return -1;
    }
    unsigned long long history[RAWSTOR_OBJECT_SYNC_ID_HISTORY];
    if (parse_sync_id_history(value, history) < 0) {
        return -1;
    }
    for (int i = 0; i < RAWSTOR_OBJECT_SYNC_ID_HISTORY; i++) {
        self->sync_id_history[i] = history[i];
    }
    return 0;
}

static PyObject*
PyObjectSyncState_get_state(PyObjectSyncState* self, void* Py_UNUSED(closure)) {
    return PyLong_FromLong(self->state);
}

static int PyObjectSyncState_set_state(
    PyObjectSyncState* self, PyObject* value, void* Py_UNUSED(closure)
) {
    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete state attribute");
        return -1;
    }
    long v = PyLong_AsLong(value);
    if (PyErr_Occurred()) {
        return -1;
    }
    self->state = (int)v;
    return 0;
}

static PyGetSetDef PyObjectSyncState_getset[] = {
    {"epoch", (getter)PyObjectSyncState_get_epoch,
     (setter)PyObjectSyncState_set_epoch, NULL, NULL},
    {"sync_id", (getter)PyObjectSyncState_get_sync_id,
     (setter)PyObjectSyncState_set_sync_id, NULL, NULL},
    {"sync_id_history", (getter)PyObjectSyncState_get_sync_id_history,
     (setter)PyObjectSyncState_set_sync_id_history, NULL, NULL},
    {"state", (getter)PyObjectSyncState_get_state,
     (setter)PyObjectSyncState_set_state, NULL, NULL},
    {NULL, NULL, NULL, NULL, NULL}
};

static PyType_Slot PyObjectSyncState_slots[] = {
    {Py_tp_dealloc, (void*)PyObjectSyncState_dealloc},
    {Py_tp_repr, (void*)PyObjectSyncState_repr},
    {Py_tp_init, (void*)PyObjectSyncState_init},
    {Py_tp_new, (void*)PyObjectSyncState_new},
    {Py_tp_getset, (void*)PyObjectSyncState_getset},
    {0, NULL},
};

static PyType_Spec PyObjectSyncState_spec = {
    .name = "rawstor.ObjectSyncState",
    .basicsize = sizeof(PyObjectSyncState),
    .itemsize = 0,
    .flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .slots = PyObjectSyncState_slots,
};

PyTypeObject* PyObjectSyncStateType = NULL;

// One mirror's metadata, as returned in the list from Target.meta()
// (object_meta() below). Output-only, like LocationInfo above -- no
// Py_tp_new/_init/setters -- there is no legitimate way for a Python
// caller to construct one and pass it back: the writer, Target.
// set_sync_state() (object_set_sync_state() below), takes an
// ObjectSyncState instead, the settable subset of these same fields.
typedef struct {
    PyObject_HEAD unsigned long long size;
    unsigned int width;
    int state;
    unsigned long long epoch;
    unsigned long long sync_id;
    unsigned long long sync_id_history[RAWSTOR_OBJECT_SYNC_ID_HISTORY];
} PyObjectMeta;

static void PyObjectMeta_dealloc(PyObjectMeta* self) {
    PyTypeObject* type = Py_TYPE(self);
    freefunc free_func = (freefunc)PyType_GetSlot(type, Py_tp_free);
    free_func(self);
    Py_DECREF(type);
}

static PyObject* PyObjectMeta_repr(PyObjectMeta* self) {
    return PyUnicode_FromFormat(
        "ObjectMeta(size=%llu, width=%u, state=%d, epoch=%llu, "
        "sync_id=%llu)",
        self->size, self->width, self->state, self->epoch, self->sync_id
    );
}

static PyObject*
PyObjectMeta_get_size(PyObjectMeta* self, void* Py_UNUSED(closure)) {
    return PyLong_FromUnsignedLongLong(self->size);
}

static PyObject*
PyObjectMeta_get_width(PyObjectMeta* self, void* Py_UNUSED(closure)) {
    return PyLong_FromUnsignedLong(self->width);
}

static PyObject*
PyObjectMeta_get_state(PyObjectMeta* self, void* Py_UNUSED(closure)) {
    return PyLong_FromLong(self->state);
}

static PyObject*
PyObjectMeta_get_epoch(PyObjectMeta* self, void* Py_UNUSED(closure)) {
    return PyLong_FromUnsignedLongLong(self->epoch);
}

static PyObject*
PyObjectMeta_get_sync_id(PyObjectMeta* self, void* Py_UNUSED(closure)) {
    return PyLong_FromUnsignedLongLong(self->sync_id);
}

static PyObject*
PyObjectMeta_get_sync_id_history(PyObjectMeta* self, void* Py_UNUSED(closure)) {
    PyObject* tuple = PyTuple_New(RAWSTOR_OBJECT_SYNC_ID_HISTORY);
    if (tuple == NULL) {
        return NULL;
    }
    for (int i = 0; i < RAWSTOR_OBJECT_SYNC_ID_HISTORY; i++) {
        PyObject* v = PyLong_FromUnsignedLongLong(self->sync_id_history[i]);
        if (v == NULL) {
            Py_DECREF(tuple);
            return NULL;
        }
        /* PyTuple_SetItem(), not the SET_ITEM macro -- this module builds
         * against the Limited API, which doesn't expose the macro form. */
        PyTuple_SetItem(tuple, i, v); /* steals ref */
    }
    return tuple;
}

static PyGetSetDef PyObjectMeta_getset[] = {
    {"size", (getter)PyObjectMeta_get_size, NULL, NULL, NULL},
    {"width", (getter)PyObjectMeta_get_width, NULL, NULL, NULL},
    {"state", (getter)PyObjectMeta_get_state, NULL, NULL, NULL},
    {"epoch", (getter)PyObjectMeta_get_epoch, NULL, NULL, NULL},
    {"sync_id", (getter)PyObjectMeta_get_sync_id, NULL, NULL, NULL},
    {"sync_id_history", (getter)PyObjectMeta_get_sync_id_history, NULL, NULL,
     NULL},
    {NULL, NULL, NULL, NULL, NULL}
};

static PyType_Slot PyObjectMeta_slots[] = {
    {Py_tp_dealloc, (void*)PyObjectMeta_dealloc},
    {Py_tp_repr, (void*)PyObjectMeta_repr},
    {Py_tp_getset, (void*)PyObjectMeta_getset},
    {0, NULL},
};

static PyType_Spec PyObjectMeta_spec = {
    .name = "rawstor.ObjectMeta",
    .basicsize = sizeof(PyObjectMeta),
    .itemsize = 0,
    .flags = Py_TPFLAGS_DEFAULT,
    .slots = PyObjectMeta_slots,
};

PyTypeObject* PyObjectMetaType = NULL;

int py_rawstor_types_init(PyObject* module) {
    PyObjectSpecType = (PyTypeObject*)PyType_FromModuleAndSpec(
        module, &PyObjectSpec_spec, NULL
    );
    if (PyObjectSpecType == NULL) {
        return -1;
    }
    if (PyModule_AddType(module, PyObjectSpecType) < 0) {
        return -1;
    }

    PyLocationInfoType = (PyTypeObject*)PyType_FromModuleAndSpec(
        module, &PyLocationInfo_spec, NULL
    );
    if (PyLocationInfoType == NULL) {
        return -1;
    }
    if (PyModule_AddType(module, PyLocationInfoType) < 0) {
        return -1;
    }

    PyObjectMetaType = (PyTypeObject*)PyType_FromModuleAndSpec(
        module, &PyObjectMeta_spec, NULL
    );
    if (PyObjectMetaType == NULL) {
        return -1;
    }
    if (PyModule_AddType(module, PyObjectMetaType) < 0) {
        return -1;
    }

    PyObjectSyncStateType = (PyTypeObject*)PyType_FromModuleAndSpec(
        module, &PyObjectSyncState_spec, NULL
    );
    if (PyObjectSyncStateType == NULL) {
        return -1;
    }
    if (PyModule_AddType(module, PyObjectSyncStateType) < 0) {
        return -1;
    }

    return 0;
}

static void free_pagination_token(PyObject* capsule) {
    if (!PyCapsule_CheckExact(capsule)) {
        return;
    }
    if (!PyCapsule_IsValid(capsule, "pagination_token")) {
        return;
    }
    RawstorPaginationToken* token = (RawstorPaginationToken*)
        PyCapsule_GetPointer(capsule, "pagination_token");
    free(token);
}

PyObject* py_rawstor_object_list(PyObject* Py_UNUSED(self), PyObject* args) {
    const char* location;
    unsigned int limit;
    PyObject* py_token;
    if (!PyArg_ParseTuple(args, "sIO", &location, &limit, &py_token)) {
        return NULL;
    }

    PyObject* py_ret_token = NULL;
    RawstorStringList* list = NULL;
    PyObject* py_list = NULL;

    RawstorPaginationToken token = {};
    if (py_token != Py_None) {
        if (!PyCapsule_CheckExact(py_token)) {
            PyErr_SetString(PyExc_TypeError, "token must be None or a capsule");
            goto error;
        }
        if (!PyCapsule_IsValid(py_token, "pagination_token")) {
            PyErr_SetString(
                PyExc_ValueError, "invalid token capsule (wrong name)"
            );
            goto error;
        }
        RawstorPaginationToken* token_ptr = (RawstorPaginationToken*)
            PyCapsule_GetPointer(py_token, "pagination_token");
        if (token_ptr == NULL) {
            goto error;
        }
        token = *token_ptr;
    }

    RawstorSyncOp op;
    int ires = rawstor_sync_op_init(&op);
    if (ires < 0) {
        set_os_error(-ires);
        goto error;
    }
    int sres = rawstor_location_list(
        op.queue, location, limit, &list, &token, rawstor_sync_op_cb, &op
    );
    ssize_t res = rawstor_sync_op_wait(&op, sres);
    rawstor_sync_op_destroy(&op);
    if (res < 0) {
        set_os_error((int)-res);
        goto error;
    }

    py_list = PyList_New(0);
    if (!py_list) {
        goto error;
    }
    for (const char** it = rawstor_string_list_iter(list); it != NULL;
         it = rawstor_string_list_next(it)) {
        PyObject* py_target = PyUnicode_FromString(*it);
        if (!py_target) {
            goto error;
        }
        if (PyList_Append(py_list, py_target) < 0) {
            Py_DECREF(py_target);
            goto error;
        }
        Py_DECREF(py_target);
    }
    rawstor_string_list_delete(list);
    list = NULL;

    if (rawstor_pagination_token_empty(&token)) {
        py_ret_token = Py_None;
        Py_INCREF(Py_None);
    } else {
        RawstorPaginationToken* ret_token =
            (RawstorPaginationToken*)malloc(sizeof(RawstorPaginationToken));
        if (ret_token == NULL) {
            PyErr_NoMemory();
            goto error;
        }
        *ret_token = token;
        py_ret_token =
            PyCapsule_New(ret_token, "pagination_token", free_pagination_token);
        if (py_ret_token == NULL) {
            free(ret_token);
            goto error;
        }
    }

    PyObject* tuple = PyTuple_New(2);
    if (!tuple) {
        goto error;
    }
    // PyTuple_SetItem() (not the PyTuple_SET_ITEM() macro) so this stays
    // Py_LIMITED_API-safe; it steals the reference just the same.
    PyTuple_SetItem(tuple, 0, py_list);
    PyTuple_SetItem(tuple, 1, py_ret_token);
    return tuple;

error:
    Py_XDECREF(py_ret_token);
    rawstor_string_list_delete(list);
    Py_XDECREF(py_list);
    return NULL;
}

PyObject* py_rawstor_object_create(PyObject* Py_UNUSED(self), PyObject* args) {
    const char* target;
    PyObject* spec_obj;

    if (!PyArg_ParseTuple(args, "sO", &target, &spec_obj)) {
        return NULL;
    }

    if (!PyObject_TypeCheck(spec_obj, PyObjectSpecType)) {
        PyErr_SetString(PyExc_TypeError, "spec must be an ObjectSpec instance");
        return NULL;
    }

    PyObjectSpec* py_spec = (PyObjectSpec*)spec_obj;
    struct RawstorObjectSpec spec = {
        .size = py_spec->size,
        .width = py_spec->width,
        .chunk_size = py_spec->chunk_size,
    };

    RawstorSyncOp op;
    int ires = rawstor_sync_op_init(&op);
    if (ires < 0) {
        set_os_error(-ires);
        return NULL;
    }
    int sres =
        rawstor_target_create(op.queue, target, &spec, rawstor_sync_op_cb, &op);
    ssize_t res = rawstor_sync_op_wait(&op, sres);
    rawstor_sync_op_destroy(&op);
    if (res < 0) {
        set_os_error((int)-res);
        return NULL;
    }

    Py_RETURN_NONE;
}

PyObject*
py_rawstor_object_create_at(PyObject* Py_UNUSED(self), PyObject* args) {
    const char* location;
    const char* uuid = NULL;
    PyObject* py_spec_obj;
    if (!PyArg_ParseTuple(args, "szO", &location, &uuid, &py_spec_obj)) {
        return NULL;
    }
    if (!PyObject_TypeCheck(py_spec_obj, PyObjectSpecType)) {
        PyErr_SetString(PyExc_TypeError, "spec must be an ObjectSpec instance");
        return NULL;
    }

    PyObjectSpec* py_spec = (PyObjectSpec*)py_spec_obj;
    struct RawstorObjectSpec spec = {
        .size = py_spec->size,
        .width = py_spec->width,
        .chunk_size = py_spec->chunk_size,
    };

    char target[65536];
    RawstorSyncOp op;
    int ires = rawstor_sync_op_init(&op);
    if (ires < 0) {
        set_os_error(-ires);
        return NULL;
    }
    int sres = rawstor_location_create(
        op.queue, location, uuid, &spec, target, sizeof(target),
        rawstor_sync_op_cb, &op
    );
    ssize_t res = rawstor_sync_op_wait(&op, sres);
    rawstor_sync_op_destroy(&op);
    if (res < 0) {
        set_os_error((int)-res);
        return NULL;
    }
    if ((size_t)res >= sizeof(target)) {
        PyErr_SetString(
            PyExc_ValueError, "rawstor_location_create(): output truncated"
        );
        return NULL;
    }

    PyObject* py_target = PyUnicode_FromString(target);
    if (!py_target) {
        return NULL;
    }

    return py_target;
}

// `snapshot_id` NULL (Python None): the version id is either already bound
// in `target`'s own path, a caller-chosen one, or a freshly generated one
// -- see rawstor_target_create_snapshot()'s own doc comment for the three
// ways this resolves. Returns the snapshot's own target string (`target`
// itself when already bound, or `target` with the id actually used spliced
// onto it otherwise) -- same shape as object_create_at() above.
PyObject*
py_rawstor_object_create_snapshot(PyObject* Py_UNUSED(self), PyObject* args) {
    const char* target;
    const char* snapshot_id = NULL;
    if (!PyArg_ParseTuple(args, "sz", &target, &snapshot_id)) {
        return NULL;
    }

    char snapshot_target[65536];

    RawstorSyncOp op;
    int ires = rawstor_sync_op_init(&op);
    if (ires < 0) {
        set_os_error(-ires);
        return NULL;
    }
    int sres = rawstor_target_create_snapshot(
        op.queue, target, snapshot_id, snapshot_target, sizeof(snapshot_target),
        rawstor_sync_op_cb, &op
    );
    ssize_t res = rawstor_sync_op_wait(&op, sres);
    rawstor_sync_op_destroy(&op);
    if (res < 0) {
        set_os_error((int)-res);
        return NULL;
    }
    if ((size_t)res >= sizeof(snapshot_target)) {
        PyErr_SetString(
            PyExc_ValueError,
            "rawstor_target_create_snapshot(): output truncated"
        );
        return NULL;
    }

    return PyUnicode_FromString(snapshot_target);
}

PyObject* py_rawstor_object_spec(PyObject* Py_UNUSED(self), PyObject* args) {
    const char* target;
    struct RawstorObjectSpec spec;

    if (!PyArg_ParseTuple(args, "s", &target)) {
        return NULL;
    }

    RawstorSyncOp op;
    int ires = rawstor_sync_op_init(&op);
    if (ires < 0) {
        set_os_error(-ires);
        return NULL;
    }
    int sres =
        rawstor_target_spec(op.queue, target, &spec, rawstor_sync_op_cb, &op);
    ssize_t res = rawstor_sync_op_wait(&op, sres);
    rawstor_sync_op_destroy(&op);
    if (res < 0) {
        set_os_error((int)-res);
        return NULL;
    }

    PyObjectSpec* py_spec = PyObject_New(PyObjectSpec, PyObjectSpecType);
    if (py_spec == NULL) {
        return NULL;
    }
    py_spec->size = spec.size;
    py_spec->width = spec.width;

    return (PyObject*)py_spec;
}

// A mirror that didn't answer is None, not an ObjectMeta with some
// sentinel field -- there is nothing meaningful to put in one, and every
// caller has to handle None from a list somewhere anyway.
static PyObject* build_mirror_meta(const struct RawstorObjectMeta* meta) {
    if (meta->sync_state.state == RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE) {
        Py_RETURN_NONE;
    }

    PyObjectMeta* py_meta = PyObject_New(PyObjectMeta, PyObjectMetaType);
    if (py_meta == NULL) {
        return NULL;
    }
    py_meta->size = meta->spec.size;
    py_meta->width = meta->spec.width;
    py_meta->state = (int)meta->sync_state.state;
    py_meta->epoch = meta->sync_state.epoch;
    py_meta->sync_id = meta->sync_state.sync_id;
    for (int i = 0; i < RAWSTOR_OBJECT_SYNC_ID_HISTORY; i++) {
        py_meta->sync_id_history[i] = meta->sync_state.sync_id_history[i];
    }
    return (PyObject*)py_meta;
}

PyObject* py_rawstor_object_meta(PyObject* Py_UNUSED(self), PyObject* args) {
    const char* target;
    unsigned long long offset = 0;
    if (!PyArg_ParseTuple(args, "s|K", &target, &offset)) {
        return NULL;
    }

    /* Same ','-separated URI count rawstor_target_create()'s own doc
     * comment describes deriving width from -- rawstor_target_meta()
     * requires its own `count` to equal this exactly. */
    size_t count = 1;
    for (const char* p = target; *p != '\0'; p++) {
        if (*p == ',') {
            count++;
        }
    }

    struct RawstorObjectMeta* metas =
        PyMem_Malloc(count * sizeof(struct RawstorObjectMeta));
    if (metas == NULL) {
        return PyErr_NoMemory();
    }

    RawstorSyncOp op;
    int ires = rawstor_sync_op_init(&op);
    if (ires < 0) {
        PyMem_Free(metas);
        set_os_error(-ires);
        return NULL;
    }
    int mres = rawstor_target_meta(
        op.queue, target, offset, metas, count, rawstor_sync_op_cb, &op
    );
    ssize_t res = rawstor_sync_op_wait(&op, mres);
    rawstor_sync_op_destroy(&op);
    if (res < 0) {
        PyMem_Free(metas);
        set_os_error((int)-res);
        return NULL;
    }

    PyObject* list = PyList_New((Py_ssize_t)count);
    if (list == NULL) {
        PyMem_Free(metas);
        return NULL;
    }
    for (size_t i = 0; i < count; i++) {
        PyObject* item = build_mirror_meta(&metas[i]);
        if (item == NULL) {
            Py_DECREF(list);
            PyMem_Free(metas);
            return NULL;
        }
        PyList_SetItem(list, (Py_ssize_t)i, item); /* steals ref */
    }
    PyMem_Free(metas);
    return list;
}

PyObject*
py_rawstor_object_set_sync_state(PyObject* Py_UNUSED(self), PyObject* args) {
    const char* target;
    PyObject* sync_state_obj;
    unsigned long long offset = 0;
    if (!PyArg_ParseTuple(args, "sO|K", &target, &sync_state_obj, &offset)) {
        return NULL;
    }

    if (!PyObject_TypeCheck(sync_state_obj, PyObjectSyncStateType)) {
        PyErr_SetString(
            PyExc_TypeError, "sync_state must be an ObjectSyncState instance"
        );
        return NULL;
    }
    PyObjectSyncState* py_sync_state = (PyObjectSyncState*)sync_state_obj;

    struct RawstorObjectSyncState sync_state = {
        .epoch = py_sync_state->epoch,
        .sync_id = py_sync_state->sync_id,
        .sync_id_history = {0},
        .state = (enum RawstorObjectSyncStateValue)py_sync_state->state,
    };
    for (int i = 0; i < RAWSTOR_OBJECT_SYNC_ID_HISTORY; i++) {
        sync_state.sync_id_history[i] = py_sync_state->sync_id_history[i];
    }

    RawstorSyncOp op;
    int ires = rawstor_sync_op_init(&op);
    if (ires < 0) {
        set_os_error(-ires);
        return NULL;
    }
    int sres = rawstor_target_set_sync_state(
        op.queue, target, offset, &sync_state, rawstor_sync_op_cb, &op
    );
    ssize_t res = rawstor_sync_op_wait(&op, sres);
    rawstor_sync_op_destroy(&op);
    if (res < 0) {
        set_os_error((int)-res);
        return NULL;
    }

    Py_RETURN_NONE;
}

PyObject* py_rawstor_object_remove(PyObject* Py_UNUSED(self), PyObject* args) {
    const char* target;
    if (!PyArg_ParseTuple(args, "s", &target)) {
        return NULL;
    }

    RawstorSyncOp op;
    int ires = rawstor_sync_op_init(&op);
    if (ires < 0) {
        set_os_error(-ires);
        return NULL;
    }
    int sres = rawstor_target_remove(op.queue, target, rawstor_sync_op_cb, &op);
    ssize_t res = rawstor_sync_op_wait(&op, sres);
    rawstor_sync_op_destroy(&op);
    if (res < 0) {
        set_os_error((int)-res);
        return NULL;
    }

    Py_RETURN_NONE;
}

// An opened object plus the queue it was opened on (an object's own I/O
// calls carry no queue argument -- it keeps the one it was opened with, so
// unlike every other binding here, this queue must outlive the call that
// created it). Owned by a PyCapsule; the destructor closes an object the
// caller never close()d.
typedef struct {
    RawIOQueue* queue;
    RawstorObject* object;
} PyObjectHandle;

typedef struct {
    size_t result;
    int error;
    int done;
} PyObjectIo;

static int py_object_io_cb(size_t result, int error, void* data) {
    PyObjectIo* io = (PyObjectIo*)data;
    io->result = result;
    io->error = error;
    io->done = 1;
    return 0;
}

static int py_object_wait(PyObjectHandle* handle, PyObjectIo* io, int res) {
    if (res < 0) {
        return res;
    }
    while (!io->done) {
        int wres = rawio_wait(handle->queue);
        if (wres < 0) {
            return wres;
        }
    }
    return -io->error;
}

static int py_object_close_sync(PyObjectHandle* handle) {
    if (handle->object == NULL) {
        return 0;
    }
    RawstorSyncOp op;
    op.queue = handle->queue;
    op.result = 0;
    op.done = 0;
    int sres = rawstor_object_close(handle->object, rawstor_sync_op_cb, &op);
    ssize_t res = rawstor_sync_op_wait(&op, sres);
    handle->object = NULL;
    return res < 0 ? (int)res : 0;
}

static void py_object_handle_free(PyObject* capsule) {
    PyObjectHandle* handle =
        (PyObjectHandle*)PyCapsule_GetPointer(capsule, "rawstor.object");
    if (handle == NULL) {
        PyErr_Clear();
        return;
    }
    py_object_close_sync(handle);
    rawio_queue_delete(handle->queue);
    free(handle);
}

static PyObjectHandle* py_object_handle_get(PyObject* capsule) {
    PyObjectHandle* handle =
        (PyObjectHandle*)PyCapsule_GetPointer(capsule, "rawstor.object");
    if (handle != NULL && handle->object == NULL) {
        PyErr_SetString(PyExc_ValueError, "object is closed");
        return NULL;
    }
    return handle;
}

// object_open(target, flags) -> handle: RAWSTOR_READONLY or 0, see
// rawstor_target_open()'s own doc comment.
PyObject* py_rawstor_object_open(PyObject* Py_UNUSED(self), PyObject* args) {
    const char* target;
    int flags;
    if (!PyArg_ParseTuple(args, "si", &target, &flags)) {
        return NULL;
    }

    PyObjectHandle* handle = (PyObjectHandle*)malloc(sizeof(PyObjectHandle));
    if (handle == NULL) {
        return PyErr_NoMemory();
    }
    handle->object = NULL;
    int ires = rawio_queue_create(16, &handle->queue);
    if (ires < 0) {
        free(handle);
        set_os_error(-ires);
        return NULL;
    }

    RawstorSyncOp op;
    op.queue = handle->queue;
    op.result = 0;
    op.done = 0;
    int sres = rawstor_target_open(
        op.queue, target, flags, &handle->object, rawstor_sync_op_cb, &op
    );
    ssize_t res = rawstor_sync_op_wait(&op, sres);
    if (res < 0) {
        rawio_queue_delete(handle->queue);
        free(handle);
        set_os_error((int)-res);
        return NULL;
    }

    PyObject* capsule =
        PyCapsule_New(handle, "rawstor.object", py_object_handle_free);
    if (capsule == NULL) {
        py_object_close_sync(handle);
        rawio_queue_delete(handle->queue);
        free(handle);
        return NULL;
    }
    return capsule;
}

// object_pread(handle, size, offset) -> bytes
PyObject* py_rawstor_object_pread(PyObject* Py_UNUSED(self), PyObject* args) {
    PyObject* capsule;
    Py_ssize_t size;
    long long offset;
    if (!PyArg_ParseTuple(args, "OnL", &capsule, &size, &offset)) {
        return NULL;
    }
    PyObjectHandle* handle = py_object_handle_get(capsule);
    if (handle == NULL) {
        return NULL;
    }
    if (size < 0) {
        PyErr_SetString(PyExc_ValueError, "size cannot be negative");
        return NULL;
    }

    char* buf = (char*)malloc(size > 0 ? (size_t)size : 1);
    if (buf == NULL) {
        return PyErr_NoMemory();
    }
    PyObjectIo io = {0, 0, 0};
    int sres = rawstor_object_pread(
        handle->object, buf, (size_t)size, (off_t)offset, py_object_io_cb, &io
    );
    int res = py_object_wait(handle, &io, sres);
    if (res < 0) {
        free(buf);
        set_os_error(-res);
        return NULL;
    }
    PyObject* ret = PyBytes_FromStringAndSize(buf, (Py_ssize_t)io.result);
    free(buf);
    return ret;
}

// object_pwrite(handle, data, offset, sync) -> number of bytes written
PyObject* py_rawstor_object_pwrite(PyObject* Py_UNUSED(self), PyObject* args) {
    PyObject* capsule;
    PyObject* data_obj;
    long long offset;
    int sync;
    if (!PyArg_ParseTuple(args, "OSLp", &capsule, &data_obj, &offset, &sync)) {
        return NULL;
    }
    PyObjectHandle* handle = py_object_handle_get(capsule);
    if (handle == NULL) {
        return NULL;
    }

    char* buf;
    Py_ssize_t len;
    if (PyBytes_AsStringAndSize(data_obj, &buf, &len) < 0) {
        return NULL;
    }

    PyObjectIo io = {0, 0, 0};
    int sres = rawstor_object_pwrite(
        handle->object, buf, (size_t)len, (off_t)offset, sync != 0,
        py_object_io_cb, &io
    );
    int res = py_object_wait(handle, &io, sres);
    if (res < 0) {
        set_os_error(-res);
        return NULL;
    }
    return PyLong_FromSize_t(io.result);
}

// object_close(handle) -> None; idempotent.
PyObject* py_rawstor_object_close(PyObject* Py_UNUSED(self), PyObject* args) {
    PyObject* capsule;
    if (!PyArg_ParseTuple(args, "O", &capsule)) {
        return NULL;
    }
    PyObjectHandle* handle =
        (PyObjectHandle*)PyCapsule_GetPointer(capsule, "rawstor.object");
    if (handle == NULL) {
        return NULL;
    }
    int res = py_object_close_sync(handle);
    if (res < 0) {
        set_os_error(-res);
        return NULL;
    }
    Py_RETURN_NONE;
}

PyObject* py_rawstor_location_info(PyObject* Py_UNUSED(self), PyObject* args) {
    const char* location;
    if (!PyArg_ParseTuple(args, "s", &location)) {
        return NULL;
    }

    struct RawstorLocationInfo info;
    RawstorSyncOp op;
    int ires = rawstor_sync_op_init(&op);
    if (ires < 0) {
        set_os_error(-ires);
        return NULL;
    }
    int sres = rawstor_location_info(
        op.queue, location, &info, rawstor_sync_op_cb, &op
    );
    ssize_t res = rawstor_sync_op_wait(&op, sres);
    rawstor_sync_op_destroy(&op);
    if (res < 0) {
        set_os_error((int)-res);
        return NULL;
    }

    PyLocationInfo* py_info = PyObject_New(PyLocationInfo, PyLocationInfoType);
    if (py_info == NULL) {
        return NULL;
    }
    py_info->used = info.used;
    py_info->total = info.total;

    return (PyObject*)py_info;
}

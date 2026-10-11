#include "rawio_sync.h"

#include <rawstor/location.h>
#include <rawstor/object.h>
#include <rawstor/target.h>

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <errno.h>
#include <string.h>

static void set_os_error(int error) {
    errno = error;
    PyErr_SetFromErrno(PyExc_OSError);
}

typedef struct {
    PyObject_HEAD unsigned long long size;
    unsigned int width;
    unsigned long long chunk_size;
    unsigned long long stripe_width;
    unsigned int failure_domain;
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
        self->stripe_width = 0;
        self->failure_domain = 0;
    }
    return (PyObject*)self;
}

static int
PyObjectSpec_init(PyObjectSpec* self, PyObject* args, PyObject* kwargs) {
    long long size;
    unsigned int width;
    unsigned long long chunk_size = 0;
    unsigned long long stripe_width = 0;
    unsigned int failure_domain = 0;
    static char* kwlist[] = {"size",         "width",          "chunk_size",
                             "stripe_width", "failure_domain", NULL};
    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs, "LI|KKI", kwlist, &size, &width, &chunk_size,
            &stripe_width, &failure_domain
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
    self->stripe_width = stripe_width;
    self->failure_domain = failure_domain;
    return 0;
}

static PyObject* PyObjectSpec_repr(PyObjectSpec* self) {
    return PyUnicode_FromFormat(
        "ObjectSpec(size=%llu, width=%u, chunk_size=%llu, stripe_width=%llu, "
        "failure_domain=%u)",
        self->size, self->width, self->chunk_size, self->stripe_width,
        self->failure_domain
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

static PyObject*
PyObjectSpec_get_stripe_width(PyObjectSpec* self, void* Py_UNUSED(closure)) {
    return PyLong_FromUnsignedLongLong(self->stripe_width);
}

static int PyObjectSpec_set_stripe_width(
    PyObjectSpec* self, PyObject* value, void* Py_UNUSED(closure)
) {
    if (value == NULL) {
        PyErr_SetString(
            PyExc_TypeError, "Cannot delete stripe_width attribute"
        );
        return -1;
    }

    unsigned long long new_stripe_width = PyLong_AsUnsignedLongLong(value);
    if (PyErr_Occurred()) {
        return -1;
    }
    self->stripe_width = new_stripe_width;
    return 0;
}

static PyObject*
PyObjectSpec_get_failure_domain(PyObjectSpec* self, void* Py_UNUSED(closure)) {
    return PyLong_FromUnsignedLong(self->failure_domain);
}

static int PyObjectSpec_set_failure_domain(
    PyObjectSpec* self, PyObject* value, void* Py_UNUSED(closure)
) {
    if (value == NULL) {
        PyErr_SetString(
            PyExc_TypeError, "Cannot delete failure_domain attribute"
        );
        return -1;
    }

    unsigned long new_failure_domain = PyLong_AsUnsignedLong(value);
    if (PyErr_Occurred()) {
        return -1;
    }
    self->failure_domain = (unsigned int)new_failure_domain;
    return 0;
}

static PyGetSetDef PyObjectSpec_getset[] = {
    {"size", (getter)PyObjectSpec_get_size, (setter)PyObjectSpec_set_size, NULL,
     NULL},
    {"width", (getter)PyObjectSpec_get_width, (setter)PyObjectSpec_set_width,
     NULL, NULL},
    {"chunk_size", (getter)PyObjectSpec_get_chunk_size,
     (setter)PyObjectSpec_set_chunk_size, NULL, NULL},
    {"stripe_width", (getter)PyObjectSpec_get_stripe_width,
     (setter)PyObjectSpec_set_stripe_width, NULL, NULL},
    {"failure_domain", (getter)PyObjectSpec_get_failure_domain,
     (setter)PyObjectSpec_set_failure_domain, NULL, NULL},
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

// The settable half of a mirror's metadata (see RawstorObjectConfig) --
// input to Target.set_member_config() (object_set_member_config()
// below), same shape/pattern as ObjectSpec above (constructible, with
// setters) since a
// caller builds one of these and passes it in, unlike ObjectMeta/
// LocationInfo below which are output-only.
typedef struct {
    PyObject_HEAD unsigned long long epoch;
    unsigned long long sync_id;
    unsigned long long sync_id_history[RAWSTOR_OBJECT_SYNC_ID_HISTORY];
    unsigned char nroles;
    unsigned char roles[RAWSTOR_OBJECT_MAX_WIDTH];
} PyObjectConfig;

static void PyObjectConfig_dealloc(PyObjectConfig* self) {
    PyTypeObject* type = Py_TYPE(self);
    freefunc free_func = (freefunc)PyType_GetSlot(type, Py_tp_free);
    free_func(self);
    Py_DECREF(type);
}

static PyObject* PyObjectConfig_new(
    PyTypeObject* type, PyObject* Py_UNUSED(args), PyObject* Py_UNUSED(kwargs)
) {
    allocfunc alloc_func = (allocfunc)PyType_GetSlot(type, Py_tp_alloc);
    PyObjectConfig* self = (PyObjectConfig*)alloc_func(type, 0);
    if (self != NULL) {
        self->epoch = 0;
        self->sync_id = 0;
        for (int i = 0; i < RAWSTOR_OBJECT_SYNC_ID_HISTORY; i++) {
            self->sync_id_history[i] = 0;
        }
        self->nroles = 0;
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

// Shared by _init and the roles setter: `value` must be a sequence of at
// most RAWSTOR_OBJECT_MAX_WIDTH RAWSTOR_OBJECT_MEMBER_* integers.
static int
parse_roles(PyObject* value, unsigned char* out, unsigned char* nroles) {
    Py_ssize_t n = PySequence_Size(value);
    if (n < 0) {
        return -1;
    }
    if (n > RAWSTOR_OBJECT_MAX_WIDTH) {
        PyErr_Format(
            PyExc_ValueError, "roles must have at most %d elements",
            RAWSTOR_OBJECT_MAX_WIDTH
        );
        return -1;
    }
    for (Py_ssize_t i = 0; i < n; i++) {
        PyObject* item = PySequence_GetItem(value, i);
        if (item == NULL) {
            return -1;
        }
        long v = PyLong_AsLong(item);
        Py_DECREF(item);
        if (PyErr_Occurred()) {
            return -1;
        }
        out[i] = (unsigned char)v;
    }
    *nroles = (unsigned char)n;
    return 0;
}

static int
PyObjectConfig_init(PyObjectConfig* self, PyObject* args, PyObject* kwargs) {
    unsigned long long epoch = 0;
    unsigned long long sync_id = 0;
    PyObject* sync_id_history_obj = NULL;
    PyObject* roles_obj = NULL;
    static char* kwlist[] = {
        "epoch", "sync_id", "sync_id_history", "roles", NULL
    };
    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs, "|KKOO", kwlist, &epoch, &sync_id,
            &sync_id_history_obj, &roles_obj
        )) {
        return -1;
    }

    unsigned char roles[RAWSTOR_OBJECT_MAX_WIDTH] = {0};
    unsigned char nroles = 0;
    if (roles_obj != NULL) {
        if (parse_roles(roles_obj, roles, &nroles) < 0) {
            return -1;
        }
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
    memcpy(self->roles, roles, sizeof(self->roles));
    self->nroles = nroles;
    return 0;
}

static PyObject* PyObjectConfig_repr(PyObjectConfig* self) {
    return PyUnicode_FromFormat(
        "ObjectConfig(epoch=%llu, sync_id=%llu, nroles=%d)", self->epoch,
        self->sync_id, (int)self->nroles
    );
}

static PyObject*
PyObjectConfig_get_epoch(PyObjectConfig* self, void* Py_UNUSED(closure)) {
    return PyLong_FromUnsignedLongLong(self->epoch);
}

static int PyObjectConfig_set_epoch(
    PyObjectConfig* self, PyObject* value, void* Py_UNUSED(closure)
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

static PyObject*
PyObjectConfig_get_sync_id(PyObjectConfig* self, void* Py_UNUSED(closure)) {
    return PyLong_FromUnsignedLongLong(self->sync_id);
}

static int PyObjectConfig_set_sync_id(
    PyObjectConfig* self, PyObject* value, void* Py_UNUSED(closure)
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

static PyObject* PyObjectConfig_get_sync_id_history(
    PyObjectConfig* self, void* Py_UNUSED(closure)
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

static int PyObjectConfig_set_sync_id_history(
    PyObjectConfig* self, PyObject* value, void* Py_UNUSED(closure)
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

static PyObject* roles_tuple(const unsigned char* roles, unsigned char nroles) {
    PyObject* tuple = PyTuple_New(nroles);
    if (tuple == NULL) {
        return NULL;
    }
    for (int i = 0; i < nroles; i++) {
        PyObject* v = PyLong_FromLong(roles[i]);
        if (v == NULL) {
            Py_DECREF(tuple);
            return NULL;
        }
        PyTuple_SetItem(tuple, i, v); /* steals ref */
    }
    return tuple;
}

static PyObject*
PyObjectConfig_get_roles(PyObjectConfig* self, void* Py_UNUSED(closure)) {
    return roles_tuple(self->roles, self->nroles);
}

static int PyObjectConfig_set_roles(
    PyObjectConfig* self, PyObject* value, void* Py_UNUSED(closure)
) {
    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete roles attribute");
        return -1;
    }
    unsigned char roles[RAWSTOR_OBJECT_MAX_WIDTH] = {0};
    unsigned char nroles = 0;
    if (parse_roles(value, roles, &nroles) < 0) {
        return -1;
    }
    memcpy(self->roles, roles, sizeof(self->roles));
    self->nroles = nroles;
    return 0;
}

static PyGetSetDef PyObjectConfig_getset[] = {
    {"epoch", (getter)PyObjectConfig_get_epoch,
     (setter)PyObjectConfig_set_epoch, NULL, NULL},
    {"sync_id", (getter)PyObjectConfig_get_sync_id,
     (setter)PyObjectConfig_set_sync_id, NULL, NULL},
    {"sync_id_history", (getter)PyObjectConfig_get_sync_id_history,
     (setter)PyObjectConfig_set_sync_id_history, NULL, NULL},
    {"roles", (getter)PyObjectConfig_get_roles,
     (setter)PyObjectConfig_set_roles, NULL, NULL},
    {NULL, NULL, NULL, NULL, NULL}
};

static PyType_Slot PyObjectConfig_slots[] = {
    {Py_tp_dealloc, (void*)PyObjectConfig_dealloc},
    {Py_tp_repr, (void*)PyObjectConfig_repr},
    {Py_tp_init, (void*)PyObjectConfig_init},
    {Py_tp_new, (void*)PyObjectConfig_new},
    {Py_tp_getset, (void*)PyObjectConfig_getset},
    {0, NULL},
};

static PyType_Spec PyObjectConfig_spec = {
    .name = "rawstor.ObjectConfig",
    .basicsize = sizeof(PyObjectConfig),
    .itemsize = 0,
    .flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .slots = PyObjectConfig_slots,
};

PyTypeObject* PyObjectConfigType = NULL;

// One mirror's metadata, as returned in the list from Target.meta()
// (object_meta() below). Output-only, like LocationInfo above -- no
// Py_tp_new/_init/setters -- there is no legitimate way for a Python
// caller to construct one and pass it back: the writer, Target.
// set_member_config() (object_set_member_config() below), takes an
// ObjectConfig instead, the settable subset of these same fields.
typedef struct {
    PyObject_HEAD unsigned long long size;
    unsigned int width;
    unsigned long long chunk_size;
    unsigned long long stripe_width;
    unsigned int failure_domain;
    int member_role;
    int state;
    int role;
    unsigned int writers;
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
        "ObjectMeta(size=%llu, width=%u, chunk_size=%llu, stripe_width=%llu, "
        "failure_domain=%u, member_role=%d, state=%d, role=%d, writers=%u, "
        "epoch=%llu, sync_id=%llu)",
        self->size, self->width, self->chunk_size, self->stripe_width,
        self->failure_domain, self->member_role, self->state, self->role,
        self->writers, self->epoch, self->sync_id
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
PyObjectMeta_get_chunk_size(PyObjectMeta* self, void* Py_UNUSED(closure)) {
    return PyLong_FromUnsignedLongLong(self->chunk_size);
}

static PyObject*
PyObjectMeta_get_stripe_width(PyObjectMeta* self, void* Py_UNUSED(closure)) {
    return PyLong_FromUnsignedLongLong(self->stripe_width);
}

static PyObject*
PyObjectMeta_get_failure_domain(PyObjectMeta* self, void* Py_UNUSED(closure)) {
    return PyLong_FromUnsignedLong(self->failure_domain);
}

static PyObject*
PyObjectMeta_get_member_role(PyObjectMeta* self, void* Py_UNUSED(closure)) {
    return PyLong_FromLong(self->member_role);
}

static PyObject*
PyObjectMeta_get_state(PyObjectMeta* self, void* Py_UNUSED(closure)) {
    return PyLong_FromLong(self->state);
}

static PyObject*
PyObjectMeta_get_role(PyObjectMeta* self, void* Py_UNUSED(closure)) {
    return PyLong_FromLong(self->role);
}

static PyObject*
PyObjectMeta_get_writers(PyObjectMeta* self, void* Py_UNUSED(closure)) {
    return PyLong_FromUnsignedLong(self->writers);
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
    {"chunk_size", (getter)PyObjectMeta_get_chunk_size, NULL, NULL, NULL},
    {"stripe_width", (getter)PyObjectMeta_get_stripe_width, NULL, NULL, NULL},
    {"failure_domain", (getter)PyObjectMeta_get_failure_domain, NULL, NULL,
     NULL},
    {"member_role", (getter)PyObjectMeta_get_member_role, NULL, NULL, NULL},
    {"state", (getter)PyObjectMeta_get_state, NULL, NULL, NULL},
    {"role", (getter)PyObjectMeta_get_role, NULL, NULL, NULL},
    {"writers", (getter)PyObjectMeta_get_writers, NULL, NULL, NULL},
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

    PyObjectConfigType = (PyTypeObject*)PyType_FromModuleAndSpec(
        module, &PyObjectConfig_spec, NULL
    );
    if (PyObjectConfigType == NULL) {
        return -1;
    }
    if (PyModule_AddType(module, PyObjectConfigType) < 0) {
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
        .stripe_width = py_spec->stripe_width,
        .failure_domain = py_spec->failure_domain,
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
        .stripe_width = py_spec->stripe_width,
        .failure_domain = py_spec->failure_domain,
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

// One rawstor_target_create_version() attempt against a fresh queue,
// driven to completion synchronously -- returns its own result unchanged
// (the version target string's own length on success, negative errno on
// failure; rawstor_sync_op_init()'s own failure already comes back in
// that same shape, a negative errno).
static ssize_t try_create_version(
    const char* target, const char* version_id, char* version_target,
    size_t size
) {
    RawstorSyncOp op;
    int ires = rawstor_sync_op_init(&op);
    if (ires < 0) {
        return ires;
    }

    int sres = rawstor_target_create_version(
        op.queue, target, version_id, version_target, size, rawstor_sync_op_cb,
        &op
    );
    ssize_t res = rawstor_sync_op_wait(&op, sres);
    rawstor_sync_op_destroy(&op);
    return res;
}

// `version_id` NULL (Python None): the version id is either already bound
// in `target`'s own path, a caller-chosen one, or a freshly generated one
// -- see rawstor_target_create_version()'s own doc comment for the three
// ways this resolves. Returns the version's own target string (`target`
// itself when already bound, or `target` with the id actually used spliced
// onto it otherwise) -- same shape as object_create_at() above.
PyObject*
py_rawstor_object_create_version(PyObject* Py_UNUSED(self), PyObject* args) {
    const char* target;
    const char* version_id = NULL;
    if (!PyArg_ParseTuple(args, "sz", &target, &version_id)) {
        return NULL;
    }

    // NULL/0 asks for the version target string's own length alone --
    // the same snprintf(NULL, 0, ...) idiom rawstor_target_create_version()
    // itself just forwards to (target.cpp), needing no I/O and creating
    // nothing. The second call, into a buffer sized exactly for that
    // length, does the real CoW.
    ssize_t res = try_create_version(target, version_id, NULL, 0);
    if (res < 0) {
        set_os_error((int)-res);
        return NULL;
    }

    char* version_target = malloc((size_t)res + 1);
    if (!version_target) {
        PyErr_NoMemory();
        return NULL;
    }

    res =
        try_create_version(target, version_id, version_target, (size_t)res + 1);
    if (res < 0) {
        free(version_target);
        set_os_error((int)-res);
        return NULL;
    }

    PyObject* py_result = PyUnicode_FromString(version_target);
    free(version_target);
    return py_result;
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
    py_spec->chunk_size = spec.chunk_size;
    py_spec->stripe_width = spec.stripe_width;
    py_spec->failure_domain = spec.failure_domain;

    return (PyObject*)py_spec;
}

// A mirror that didn't answer is None, not an ObjectMeta with some
// sentinel field -- there is nothing meaningful to put in one, and every
// caller has to handle None from a list somewhere anyway.
// `index`: the mirror's position among the chunk's members, which is its
// position in the configuration's roles.
static PyObject*
build_mirror_meta(const struct RawstorObjectMeta* meta, ssize_t index) {
    if (meta->state == RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE) {
        Py_RETURN_NONE;
    }

    PyObjectMeta* py_meta = PyObject_New(PyObjectMeta, PyObjectMetaType);
    if (py_meta == NULL) {
        return NULL;
    }
    py_meta->size = meta->spec.size;
    py_meta->width = meta->spec.width;
    py_meta->chunk_size = meta->spec.chunk_size;
    py_meta->stripe_width = meta->spec.stripe_width;
    py_meta->failure_domain = meta->spec.failure_domain;
    py_meta->member_role = (int)meta->member_role;
    py_meta->state = (int)meta->state;
    py_meta->role = index < (ssize_t)meta->config.nroles
                        ? meta->config.roles[index]
                        : RAWSTOR_OBJECT_MEMBER_UNKNOWN;
    py_meta->writers = meta->writers;
    py_meta->epoch = meta->config.epoch;
    py_meta->sync_id = meta->config.sync_id;
    for (int i = 0; i < RAWSTOR_OBJECT_SYNC_ID_HISTORY; i++) {
        py_meta->sync_id_history[i] = meta->config.sync_id_history[i];
    }
    return (PyObject*)py_meta;
}

PyObject* py_rawstor_object_meta(PyObject* Py_UNUSED(self), PyObject* args) {
    const char* target;
    unsigned long long offset = 0;
    if (!PyArg_ParseTuple(args, "s|K", &target, &offset)) {
        return NULL;
    }

    /* One entry per ','-separated URI in `target` is the first guess; the
     * real member count comes back as the result (an mds:// target
     * reports every member of the chunk), and a bigger one means the
     * call has to be repeated with room for all of them. */
    size_t count = 1;
    for (const char* p = target; *p != '\0'; p++) {
        if (*p == ',') {
            count++;
        }
    }

    struct RawstorObjectMeta* metas = NULL;
    ssize_t res;
    for (;;) {
        struct RawstorObjectMeta* new_metas =
            PyMem_Realloc(metas, count * sizeof(struct RawstorObjectMeta));
        if (new_metas == NULL) {
            PyMem_Free(metas);
            return PyErr_NoMemory();
        }
        metas = new_metas;

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
        res = rawstor_sync_op_wait(&op, mres);
        rawstor_sync_op_destroy(&op);
        if (res < 0) {
            PyMem_Free(metas);
            set_os_error((int)-res);
            return NULL;
        }
        if ((size_t)res <= count) {
            break;
        }
        count = (size_t)res;
    }
    count = (size_t)res;

    PyObject* list = PyList_New((Py_ssize_t)count);
    if (list == NULL) {
        PyMem_Free(metas);
        return NULL;
    }
    for (size_t i = 0; i < count; i++) {
        PyObject* item = build_mirror_meta(&metas[i], (ssize_t)i);
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
py_rawstor_object_set_member_config(PyObject* Py_UNUSED(self), PyObject* args) {
    const char* target;
    PyObject* config_obj;
    unsigned long long member_index = 0;
    unsigned long long offset = 0;
    unsigned int flags = 0;
    if (!PyArg_ParseTuple(
            args, "sO|KKI", &target, &config_obj, &member_index, &offset, &flags
        )) {
        return NULL;
    }

    if (!PyObject_TypeCheck(config_obj, PyObjectConfigType)) {
        PyErr_SetString(
            PyExc_TypeError, "config must be an ObjectConfig instance"
        );
        return NULL;
    }
    PyObjectConfig* py_config = (PyObjectConfig*)config_obj;

    struct RawstorObjectConfig config;
    memset(&config, 0, sizeof(config));
    config.epoch = py_config->epoch;
    config.sync_id = py_config->sync_id;
    for (int i = 0; i < RAWSTOR_OBJECT_SYNC_ID_HISTORY; i++) {
        config.sync_id_history[i] = py_config->sync_id_history[i];
    }
    config.nroles = py_config->nroles;
    memcpy(config.roles, py_config->roles, py_config->nroles);

    RawstorSyncOp op;
    int ires = rawstor_sync_op_init(&op);
    if (ires < 0) {
        set_os_error(-ires);
        return NULL;
    }
    int sres = rawstor_target_set_member_config(
        op.queue, target, offset, (size_t)member_index, &config, flags,
        rawstor_sync_op_cb, &op
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

PyObject* py_rawstor_object_chunks(PyObject* Py_UNUSED(self), PyObject* args) {
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
    /* A first call for the count, a second for the offsets themselves --
     * rawstor_target_chunks()'s own NULL/0 convention. */
    int sres = rawstor_target_chunks(
        op.queue, target, NULL, 0, rawstor_sync_op_cb, &op
    );
    ssize_t count = rawstor_sync_op_wait(&op, sres);
    uint64_t* offsets = NULL;
    if (count > 0) {
        offsets = (uint64_t*)malloc((size_t)count * sizeof(*offsets));
        if (offsets == NULL) {
            rawstor_sync_op_destroy(&op);
            return PyErr_NoMemory();
        }
        op.done = 0;
        sres = rawstor_target_chunks(
            op.queue, target, offsets, (size_t)count, rawstor_sync_op_cb, &op
        );
        ssize_t filled = rawstor_sync_op_wait(&op, sres);
        if (filled >= 0 && filled < count) {
            count = filled;
        } else if (filled < 0) {
            count = filled;
        }
    }
    rawstor_sync_op_destroy(&op);
    if (count < 0) {
        free(offsets);
        set_os_error((int)-count);
        return NULL;
    }

    PyObject* py_list = PyList_New(0);
    if (py_list == NULL) {
        free(offsets);
        return NULL;
    }
    for (ssize_t i = 0; i < count; ++i) {
        PyObject* py_offset = PyLong_FromUnsignedLongLong(offsets[i]);
        if (py_offset == NULL || PyList_Append(py_list, py_offset) < 0) {
            Py_XDECREF(py_offset);
            Py_DECREF(py_list);
            free(offsets);
            return NULL;
        }
        Py_DECREF(py_offset);
    }
    free(offsets);
    return py_list;
}

PyObject*
py_rawstor_object_versions(PyObject* Py_UNUSED(self), PyObject* args) {
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
    RawstorStringList* list = NULL;
    int sres = rawstor_target_versions(
        op.queue, target, &list, rawstor_sync_op_cb, &op
    );
    ssize_t res = rawstor_sync_op_wait(&op, sres);
    rawstor_sync_op_destroy(&op);
    if (res < 0) {
        set_os_error((int)-res);
        return NULL;
    }

    PyObject* py_list = PyList_New(0);
    if (py_list == NULL) {
        rawstor_string_list_delete(list);
        return NULL;
    }
    for (const char** it = rawstor_string_list_iter(list); it != NULL;
         it = rawstor_string_list_next(it)) {
        PyObject* py_target = PyUnicode_FromString(*it);
        if (py_target == NULL || PyList_Append(py_list, py_target) < 0) {
            Py_XDECREF(py_target);
            Py_DECREF(py_list);
            rawstor_string_list_delete(list);
            return NULL;
        }
        Py_DECREF(py_target);
    }
    rawstor_string_list_delete(list);
    return py_list;
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

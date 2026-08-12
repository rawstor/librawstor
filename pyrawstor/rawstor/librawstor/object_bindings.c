#include <rawstor/location.h>
#include <rawstor/object.h>

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
    }
    return (PyObject*)self;
}

static int
PyObjectSpec_init(PyObjectSpec* self, PyObject* args, PyObject* kwargs) {
    long long size = 0;
    static char* kwlist[] = {"size", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|L", kwlist, &size)) {
        return -1;
    }
    if (size < 0) {
        PyErr_SetString(PyExc_ValueError, "size cannot be negative");
        return -1;
    }
    self->size = (unsigned long long)size;
    return 0;
}

static PyObject* PyObjectSpec_repr(PyObjectSpec* self) {
    return PyUnicode_FromFormat("ObjectSpec(size=%llu)", self->size);
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

static PyGetSetDef PyObjectSpec_getset[] = {
    {"size", (getter)PyObjectSpec_get_size, (setter)PyObjectSpec_set_size, NULL,
     NULL},
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

    int res = rawstor_object_list(location, limit, &list, &token);
    if (res < 0) {
        set_os_error(-res);
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
    struct RawstorObjectSpec spec;

    if (!PyArg_ParseTuple(args, "sO", &target, &spec_obj)) {
        return NULL;
    }

    if (!PyObject_TypeCheck(spec_obj, PyObjectSpecType)) {
        PyErr_SetString(PyExc_TypeError, "spec must be an ObjectSpec instance");
        return NULL;
    }

    PyObjectSpec* py_spec = (PyObjectSpec*)spec_obj;
    spec.size = py_spec->size;

    int res = rawstor_object_create(target, &spec);
    if (res < 0) {
        set_os_error(-res);
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
    };

    char target[65536];
    int res =
        rawstor_object_create_at(location, uuid, &spec, target, sizeof(target));
    if (res < 0) {
        set_os_error(-res);
        return NULL;
    }
    if ((size_t)res >= sizeof(target)) {
        PyErr_SetString(
            PyExc_ValueError, "rawstor_object_create_at(): output truncated"
        );
        return NULL;
    }

    PyObject* py_target = PyUnicode_FromString(target);
    if (!py_target) {
        return NULL;
    }

    return py_target;
}

PyObject* py_rawstor_object_spec(PyObject* Py_UNUSED(self), PyObject* args) {
    const char* target;
    struct RawstorObjectSpec spec;

    if (!PyArg_ParseTuple(args, "s", &target)) {
        return NULL;
    }

    int res = rawstor_object_spec(target, &spec);
    if (res < 0) {
        set_os_error(-res);
        return NULL;
    }

    PyObjectSpec* py_spec = PyObject_New(PyObjectSpec, PyObjectSpecType);
    if (py_spec == NULL) {
        return NULL;
    }
    py_spec->size = spec.size;

    return (PyObject*)py_spec;
}

PyObject* py_rawstor_object_remove(PyObject* Py_UNUSED(self), PyObject* args) {
    const char* target;
    if (!PyArg_ParseTuple(args, "s", &target)) {
        return NULL;
    }

    int res = rawstor_object_remove(target);
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
    int res = rawstor_location_info(location, &info);
    if (res < 0) {
        set_os_error(-res);
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

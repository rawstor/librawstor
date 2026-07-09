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

static void PyObjectSpec_dealloc(PyObjectSpec* self) {
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject* PyObjectSpec_new(
    PyTypeObject* type, PyObject* Py_UNUSED(args), PyObject* Py_UNUSED(kwargs)
) {
    PyObjectSpec* self = (PyObjectSpec*)type->tp_alloc(type, 0);
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

PyTypeObject PyObjectSpecType = {
    PyVarObject_HEAD_INIT(NULL, 0).tp_name = "rawstor.ObjectSpec",
    .tp_basicsize = sizeof(PyObjectSpec),
    .tp_dealloc = (destructor)PyObjectSpec_dealloc,
    .tp_repr = (reprfunc)PyObjectSpec_repr,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_init = (initproc)PyObjectSpec_init,
    .tp_new = PyObjectSpec_new,
    .tp_getset = PyObjectSpec_getset,
};

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
            return NULL;
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
    PyTuple_SET_ITEM(tuple, 0, py_list);
    PyTuple_SET_ITEM(tuple, 1, py_ret_token);
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

    if (!PyObject_TypeCheck(spec_obj, &PyObjectSpecType)) {
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
    if (!PyObject_TypeCheck(py_spec_obj, &PyObjectSpecType)) {
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

    PyObjectSpec* py_spec = PyObject_New(PyObjectSpec, &PyObjectSpecType);
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

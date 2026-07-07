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

PyObject* py_rawstor_object_list(PyObject* Py_UNUSED(self), PyObject* args) {
    PyObject* new_marker_obj = NULL;
    PyObject* tuple = NULL;

    const char* location;
    unsigned int limit;
    PyObject* marker_obj;
    if (!PyArg_ParseTuple(args, "sIO", &location, &limit, &marker_obj)) {
        return NULL;
    }

    void* marker_ptr = NULL;
    if (marker_obj != Py_None) {
        if (!PyCapsule_CheckExact(marker_obj)) {
            PyErr_SetString(
                PyExc_TypeError, "marker must be None or a capsule"
            );
            return NULL;
        }
        marker_ptr = PyCapsule_GetPointer(marker_obj, "marker");
        if (marker_ptr == NULL) {
            return NULL;
        }
    }

    RawstorStringList* list = NULL;
    PyObject* py_list = NULL;
    int res = rawstor_object_list(location, limit, &list, &marker_ptr);

    if (marker_obj != Py_None) {
        Py_DECREF(marker_obj);
    }

    if (res < 0) {
        set_os_error(-res);
        goto error;
    }

    py_list = PyList_New(0);
    if (!py_list) {
        goto error;
    }

    const char** iter = rawstor_string_list_iter(list);
    while (iter != NULL) {
        const char* target = *iter;
        PyObject* py_target = PyUnicode_FromString(target);
        if (!py_target) {
            goto error;
        }
        if (PyList_Append(py_list, py_target) < 0) {
            Py_DECREF(py_target);
            goto error;
        }
        Py_DECREF(py_target);
        iter = rawstor_string_list_next(iter);
    }

    if (marker_ptr != NULL) {
        new_marker_obj =
            PyCapsule_New(marker_ptr, "marker", (PyCapsule_Destructor)free);
        if (new_marker_obj == NULL) {
            goto error;
        }
    } else {
        new_marker_obj = Py_None;
        Py_INCREF(Py_None);
    }

    rawstor_string_list_delete(list);

    tuple = PyTuple_New(2);
    if (!tuple) {
        goto error;
    }
    PyTuple_SET_ITEM(tuple, 0, py_list);
    PyTuple_SET_ITEM(tuple, 1, new_marker_obj);
    return tuple;

error:
    if (list) {
        rawstor_string_list_delete(list);
    }
    if (marker_ptr != NULL && new_marker_obj == NULL) {
        free(marker_ptr);
    }
    if (py_list != NULL) {
        Py_DECREF(py_list);
    }
    if (new_marker_obj != NULL) {
        Py_DECREF(new_marker_obj);
    }
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

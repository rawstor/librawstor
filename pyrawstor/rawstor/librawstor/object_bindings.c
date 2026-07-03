#include <rawstor/object.h>

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <string.h>

static void set_os_error(int error) {
    PyObject* args = Py_BuildValue("(is)", error, strerror(error));
    if (!args) {
        return;
    }

    PyErr_SetObject(PyExc_OSError, args);
    Py_DECREF(args);
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
    unsigned long long size = 0;
    static char* kwlist[] = {"size", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|K", kwlist, &size)) {
        return -1;
    }
    self->size = size;
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

    if (!PyArg_ParseTuple(args, "s|zO", &location, &uuid, &py_spec_obj))
        return NULL;

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
    if ((size_t)res > sizeof(target)) {
        PyErr_SetString(
            PyExc_TypeError, "rawstor_object_create_at(): output truncated"
        );
        return NULL;
    }

    PyObject* py_target = PyUnicode_FromString(target);
    if (!py_target) {
        PyErr_NoMemory();
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

    PyObjectSpec* py_spec =
        (PyObjectSpec*)PyObjectSpecType.tp_new(&PyObjectSpecType, NULL, NULL);
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

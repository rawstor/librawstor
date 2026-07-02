#include <rawstor/object.h>

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <string.h>

PyObject* py_rawstor_object_create(
    PyObject* Py_UNUSED(self), PyObject* Py_UNUSED(args),
    PyObject* Py_UNUSED(kwargs)
) {
    return PyLong_FromLong(0);
}

PyObject* py_rawstor_object_remove(PyObject* Py_UNUSED(self), PyObject* args) {
    const char* target;
    if (!PyArg_ParseTuple(args, "s", &target)) {
        return NULL;
    }

    int res = rawstor_object_remove(target);

    return PyLong_FromLong(res);
}

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "object_bindings.h"

#include <rawstor/rawstor.h>

#include <string.h>

static PyMethodDef librawstor_methods[] = {
    {"object_create", py_rawstor_object_create, METH_VARARGS, NULL},
    {"object_create_at", py_rawstor_object_create_at, METH_VARARGS, NULL},
    {"object_spec", py_rawstor_object_spec, METH_VARARGS, NULL},
    {"object_remove", py_rawstor_object_remove, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static void librawstor_free(void* Py_UNUSED(module)) {
    rawstor_terminate();
}

static struct PyModuleDef librawstor_module = {
    .m_base = PyModuleDef_HEAD_INIT,
    .m_name = "librawstor",
    .m_doc = NULL,
    .m_size = -1,
    .m_methods = librawstor_methods,
    .m_slots = NULL,
    .m_traverse = NULL,
    .m_clear = NULL,
    .m_free = librawstor_free,
};

PyMODINIT_FUNC PyInit_librawstor() {
    int res = rawstor_initialize(NULL);
    if (res < 0) {
        PyErr_Format(
            PyExc_RuntimeError, "rawstor_initialize() failed: %s",
            strerror(-res)
        );
        return NULL;
    }

    if (PyType_Ready(&PyObjectSpecType) < 0) {
        rawstor_terminate();
        return NULL;
    }

    PyObject* module = PyModule_Create(&librawstor_module);
    if (module == NULL) {
        rawstor_terminate();
        return NULL;
    }

    Py_INCREF(&PyObjectSpecType);
    if (PyModule_AddObject(module, "ObjectSpec", (PyObject*)&PyObjectSpecType) <
        0) {
        Py_DECREF(&PyObjectSpecType);
        Py_DECREF(module);
        rawstor_terminate();
        return NULL;
    }

    return module;
}

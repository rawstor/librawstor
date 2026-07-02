#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "object_bindings.h"

#include <rawstor/rawstor.h>

#include <string.h>

static PyMethodDef librawstor_methods[] = {
    {"object_create", _PyCFunction_CAST(py_rawstor_object_create),
     METH_VARARGS | METH_KEYWORDS, NULL},
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

    PyObject* module = PyModule_Create(&librawstor_module);
    if (module == NULL) {
        return NULL;
    }

    return module;
}

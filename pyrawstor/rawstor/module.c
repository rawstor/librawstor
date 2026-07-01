#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "rawstor_bindings.h"

static PyMethodDef rawstor_methods[] = {
    {"initialize", py_rawstor_initialize, METH_VARARGS, NULL},
    {"terminate", py_rawstor_terminate, METH_NOARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef rawstor_module = {
    .m_base = PyModuleDef_HEAD_INIT,
    .m_name = "rawstor",
    .m_doc = NULL,
    .m_size = -1,
    .m_methods = rawstor_methods,
    .m_slots = NULL,
    .m_traverse = NULL,
    .m_clear = NULL,
    .m_free = NULL,
};

PyMODINIT_FUNC PyInit_rawstor() {
    PyObject* m = PyModule_Create(&rawstor_module);
    if (m == NULL) {
        return NULL;
    }

    return m;
}

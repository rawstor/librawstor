#define PY_SSIZE_T_CLEAN
#include <Python.h>

static struct PyModuleDef rawstor_module = {
    PyModuleDef_HEAD_INIT,
    "rawstor",
    NULL,
    -1,
};

PyMODINIT_FUNC PyInit_rawstor() {
    PyObject* m = PyModule_Create(&rawstor_module);
    if (m == NULL) {
        return NULL;
    }

    return m;
}

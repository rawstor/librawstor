#ifndef PYRAWSTOR_RAWSTOR_BINDINGS_H
#define PYRAWSTOR_RAWSTOR_BINDINGS_H

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#ifdef __cplusplus
extern "C" {
#endif

PyObject* py_rawstor_initialize(PyObject* self, PyObject* args);

PyObject* py_rawstor_terminate(PyObject* self, PyObject* args);

#ifdef __cplusplus
}
#endif

#endif // PYRAWSTOR_RAWSTOR_BINDINGS_H

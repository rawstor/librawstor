#ifndef PYRAWSTOR_OBJECT_BINDINGS_H
#define PYRAWSTOR_OBJECT_BINDINGS_H

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#ifdef __cplusplus
extern "C" {
#endif

PyObject*
py_rawstor_object_create(PyObject* self, PyObject* args, PyObject* kwargs);

PyObject* py_rawstor_object_remove(PyObject* self, PyObject* args);

#ifdef __cplusplus
}
#endif

#endif // PYRAWSTOR_OBJECT_BINDINGS_H

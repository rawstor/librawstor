#ifndef PYRAWSTOR_OBJECT_BINDINGS_H
#define PYRAWSTOR_OBJECT_BINDINGS_H

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#ifdef __cplusplus
extern "C" {
#endif

// Heap types (Py_LIMITED_API-compatible, built via PyType_FromModuleAndSpec)
// -- NULL until py_rawstor_types_init() creates them at module init time.
extern PyTypeObject* PyObjectSpecType;
extern PyTypeObject* PyLocationInfoType;

int py_rawstor_types_init(PyObject* module);

PyObject* py_rawstor_object_list(PyObject* self, PyObject* args);

PyObject* py_rawstor_object_create(PyObject* self, PyObject* args);

PyObject* py_rawstor_object_create_at(PyObject* self, PyObject* args);

PyObject* py_rawstor_object_spec(PyObject* self, PyObject* args);

PyObject* py_rawstor_object_remove(PyObject* self, PyObject* args);

PyObject* py_rawstor_location_info(PyObject* self, PyObject* args);

#ifdef __cplusplus
}
#endif

#endif // PYRAWSTOR_OBJECT_BINDINGS_H

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "object_bindings.h"

#include <rawstor/rawstor.h>

#include <string.h>

static PyMethodDef librawstor_methods[] = {
    {"object_list", py_rawstor_object_list, METH_VARARGS, NULL},
    {"object_create", py_rawstor_object_create, METH_VARARGS, NULL},
    {"object_create_at", py_rawstor_object_create_at, METH_VARARGS, NULL},
    {"object_create_version", py_rawstor_object_create_version, METH_VARARGS,
     NULL},
    {"object_spec", py_rawstor_object_spec, METH_VARARGS, NULL},
    {"object_meta", py_rawstor_object_meta, METH_VARARGS, NULL},
    {"object_sync_accept", py_rawstor_object_sync_accept, METH_VARARGS, NULL},
    {"object_remove", py_rawstor_object_remove, METH_VARARGS, NULL},
    {"object_resize", py_rawstor_object_resize, METH_VARARGS, NULL},
    {"object_transfer", py_rawstor_object_transfer, METH_VARARGS, NULL},
    {"object_chunks", py_rawstor_object_chunks, METH_VARARGS, NULL},
    {"object_slots", py_rawstor_object_slots, METH_VARARGS, NULL},
    {"object_versions", py_rawstor_object_versions, METH_VARARGS, NULL},
    {"object_export", py_rawstor_object_export, METH_VARARGS, NULL},
    {"object_create_at_from_file", py_rawstor_object_create_at_from_file,
     METH_VARARGS, NULL},
    {"object_create_at_from_target", py_rawstor_object_create_at_from_target,
     METH_VARARGS, NULL},
    {"object_create_from_file", py_rawstor_object_create_from_file,
     METH_VARARGS, NULL},
    {"object_create_from_target", py_rawstor_object_create_from_target,
     METH_VARARGS, NULL},
    {"location_info", py_rawstor_location_info, METH_VARARGS, NULL},
    {"account_list", py_rawstor_account_list, METH_VARARGS, NULL},
    {"account_create", py_rawstor_account_create, METH_VARARGS, NULL},
    {"account_remove", py_rawstor_account_remove, METH_VARARGS, NULL},
    {"target_account", py_rawstor_target_account, METH_VARARGS, NULL},
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
    PyObject* package = PyImport_ImportModule("rawstor");
    if (package == NULL) {
        return NULL;
    }
    PyObject* insecure =
        PyObject_GetAttrString(package, "_initialize_insecure");
    Py_DECREF(package);
    if (insecure == NULL) {
        return NULL;
    }
    PyObject* requested = PyObject_CallMethod(insecure, "get", NULL);
    Py_DECREF(insecure);
    if (requested == NULL) {
        return NULL;
    }
    int enabled = PyObject_IsTrue(requested);
    Py_DECREF(requested);
    if (enabled < 0) {
        return NULL;
    }
    struct RawstorOpts opts = {0};
    opts.insecure = enabled ? 1u : 0u;
    int res = rawstor_initialize(&opts);
    if (res < 0) {
        PyErr_Format(
            PyExc_RuntimeError, "rawstor_initialize() failed: %s",
            strerror(-res)
        );
        return NULL;
    }

    PyObject* module = PyModule_Create(&librawstor_module);
    if (module == NULL) {
        rawstor_terminate();
        return NULL;
    }

    if (PyModule_AddIntConstant(module, "_insecure", enabled) < 0 ||
        py_rawstor_types_init(module) < 0) {
        Py_DECREF(module);
        return NULL;
    }

    return module;
}

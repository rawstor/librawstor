#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "object_bindings.h"

#include <rawstor/protocol.h>
#include <rawstor/rawstor.h>
#include <rawstor/target.h>

#include <string.h>

static PyMethodDef librawstor_methods[] = {
    {"object_list", py_rawstor_object_list, METH_VARARGS, NULL},
    {"object_create", py_rawstor_object_create, METH_VARARGS, NULL},
    {"object_create_at", py_rawstor_object_create_at, METH_VARARGS, NULL},
    {"object_create_snapshot", py_rawstor_object_create_snapshot, METH_VARARGS,
     NULL},
    {"object_spec", py_rawstor_object_spec, METH_VARARGS, NULL},
    {"object_meta", py_rawstor_object_meta, METH_VARARGS, NULL},
    {"object_set_member_sync_state", py_rawstor_object_set_member_sync_state,
     METH_VARARGS, NULL},
    {"object_remove", py_rawstor_object_remove, METH_VARARGS, NULL},
    {"object_chunks", py_rawstor_object_chunks, METH_VARARGS, NULL},
    {"object_snapshots", py_rawstor_object_snapshots, METH_VARARGS, NULL},
    {"location_info", py_rawstor_location_info, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

// Values of ObjectSpec.failure_domain, ObjectSyncState.state/
// ObjectMeta.state and ObjectMeta.member_role.
static int add_constants(PyObject* module) {
    static const struct {
        const char* name;
        long value;
    } constants[] = {
        {"OBJ_DOMAIN_DEFAULT", RAWSTOR_OBJ_DOMAIN_DEFAULT},
        {"OBJ_DOMAIN_OST", RAWSTOR_OBJ_DOMAIN_OST},
        {"OBJ_DOMAIN_SERVER", RAWSTOR_OBJ_DOMAIN_SERVER},
        {"OBJ_DOMAIN_RACK", RAWSTOR_OBJ_DOMAIN_RACK},
        {"OBJ_DOMAIN_ROW", RAWSTOR_OBJ_DOMAIN_ROW},
        {"OBJ_DOMAIN_DC", RAWSTOR_OBJ_DOMAIN_DC},
        {"OBJECT_SYNC_STATE_UNREACHABLE",
         RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE},
        {"OBJECT_SYNC_STATE_CLEAN", RAWSTOR_OBJECT_SYNC_STATE_CLEAN},
        {"OBJECT_SYNC_STATE_DIRTY", RAWSTOR_OBJECT_SYNC_STATE_DIRTY},
        {"OBJECT_SYNC_STATE_SYNCING", RAWSTOR_OBJECT_SYNC_STATE_SYNCING},
        {"MEMBER_DATA", RAWSTOR_MEMBER_DATA},
        {"MEMBER_WITNESS", RAWSTOR_MEMBER_WITNESS},
    };
    for (size_t i = 0; i < sizeof(constants) / sizeof(constants[0]); i++) {
        if (PyModule_AddIntConstant(
                module, constants[i].name, constants[i].value
            ) < 0) {
            return -1;
        }
    }
    return 0;
}

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
        rawstor_terminate();
        return NULL;
    }

    if (py_rawstor_types_init(module) < 0 || add_constants(module) < 0) {
        Py_DECREF(module);
        rawstor_terminate();
        return NULL;
    }

    return module;
}

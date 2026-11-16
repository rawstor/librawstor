#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <rawstor/pki.h>

#include <string.h>

/* The extension is separate from librawstor on purpose: importing librawstor
 * initializes rawstor, which needs TLS settings, and these are the functions
 * that make them. Nothing here initializes rawstor. */

static PyObject* pki_error(int res) {
    PyObject* args = Py_BuildValue("(is)", -res, rawstor_pki_error());
    if (args != NULL) {
        /* Calling OSError with an errno gives the subclass for it:
         * FileNotFoundError, FileExistsError, ... */
        PyObject* exc = PyObject_Call(PyExc_OSError, args, NULL);
        Py_DECREF(args);
        if (exc != NULL) {
            PyErr_SetObject((PyObject*)Py_TYPE(exc), exc);
            Py_DECREF(exc);
        }
    }
    return NULL;
}

static PyObject* py_pki_init(PyObject* Py_UNUSED(self), PyObject* args) {
    const char* dir;
    const char* trust_domain;
    unsigned long validity;
    if (!PyArg_ParseTuple(args, "ssk", &dir, &trust_domain, &validity)) {
        return NULL;
    }
    int res;
    Py_BEGIN_ALLOW_THREADS;
    res = rawstor_pki_init(dir, trust_domain, validity);
    Py_END_ALLOW_THREADS;
    if (res < 0) {
        return pki_error(res);
    }
    Py_RETURN_NONE;
}

/* issue(dir, role, tenant, name, validity, cert_file, key_file) -> identity,
 * the role being the RawstorPkiRole as an int and tenant and name None where
 * the role has none. */
static PyObject* py_pki_issue(PyObject* Py_UNUSED(self), PyObject* args) {
    const char* dir;
    int role;
    const char* tenant;
    const char* name;
    unsigned long validity;
    const char* cert_file;
    const char* key_file;
    unsigned int access_role = 0;
    PyObject* object_permissions = Py_None;
    if (!PyArg_ParseTuple(
            args, "sizzkss|IO", &dir, &role, &tenant, &name, &validity,
            &cert_file, &key_file, &access_role, &object_permissions
        )) {
        return NULL;
    }
    struct RawstorPkiPermissions permissions = {0};
    permissions.role = access_role;
    if (object_permissions != Py_None) {
        if (!PyDict_Check(object_permissions) ||
            PyDict_Size(object_permissions) >
                RAWSTOR_PKI_MAX_OBJECT_PERMISSIONS) {
            PyErr_SetString(
                PyExc_ValueError,
                "object_permissions must be a dict with at most 128 entries"
            );
            return NULL;
        }
        Py_ssize_t position = 0;
        PyObject* key;
        PyObject* value;
        while (PyDict_Next(object_permissions, &position, &key, &value)) {
            Py_ssize_t size;
            PyObject* encoded = PyUnicode_AsUTF8String(key);
            if (!encoded)
                return NULL;
            char* object;
            if (PyBytes_AsStringAndSize(encoded, &object, &size) < 0) {
                Py_DECREF(encoded);
                return NULL;
            }
            unsigned long mask = PyLong_AsUnsignedLong(value);
            if (PyErr_Occurred()) {
                Py_DECREF(encoded);
                return NULL;
            }
            if (size != 36 || memchr(object, 0, (size_t)size) ||
                mask > RAWSTOR_PERM_ALL) {
                Py_DECREF(encoded);
                PyErr_SetString(
                    PyExc_ValueError,
                    "object_permissions requires UUID keys and masks in 0..15"
                );
                return NULL;
            }
            struct RawstorPkiObjectPermissions* entry =
                &permissions.objects[permissions.count++];
            memcpy(entry->object_id, object, 36);
            Py_DECREF(encoded);
            entry->object_id[36] = '\0';
            entry->permissions = (unsigned int)mask;
        }
    }
    char identity[RAWSTOR_PKI_IDENTITY_SIZE];
    int res;
    Py_BEGIN_ALLOW_THREADS;
    res = rawstor_pki_issue(
        dir, (enum RawstorPkiRole)role, tenant, name, validity, cert_file,
        key_file, identity, sizeof(identity), &permissions
    );
    Py_END_ALLOW_THREADS;
    if (res < 0) {
        return pki_error(res);
    }
    return PyUnicode_FromString(identity);
}

static PyObject* py_pki_renew(PyObject* Py_UNUSED(self), PyObject* args) {
    const char* dir;
    const char* cert_file;
    const char* key_file;
    unsigned long validity;
    if (!PyArg_ParseTuple(
            args, "sssk", &dir, &cert_file, &key_file, &validity
        )) {
        return NULL;
    }
    char identity[RAWSTOR_PKI_IDENTITY_SIZE];
    int res;
    Py_BEGIN_ALLOW_THREADS;
    res = rawstor_pki_renew(
        dir, cert_file, key_file, validity, identity, sizeof(identity)
    );
    Py_END_ALLOW_THREADS;
    if (res < 0) {
        return pki_error(res);
    }
    return PyUnicode_FromString(identity);
}

/* show(cert_file, dir) -> (identity, not_after, issued), dir None without a
 * CA and issued None then, otherwise a bool. */
static PyObject* py_pki_show(PyObject* Py_UNUSED(self), PyObject* args) {
    const char* cert_file;
    const char* dir;
    if (!PyArg_ParseTuple(args, "sz", &cert_file, &dir)) {
        return NULL;
    }
    struct RawstorPkiInfo info;
    int res;
    Py_BEGIN_ALLOW_THREADS;
    res = rawstor_pki_show(cert_file, dir, &info);
    Py_END_ALLOW_THREADS;
    if (res < 0) {
        return pki_error(res);
    }
    PyObject* issued;
    if (info.issued < 0) {
        issued = Py_None;
        Py_INCREF(issued);
    } else {
        issued = PyBool_FromLong(info.issued);
    }
    PyObject* restrictions = PyDict_New();
    if (!restrictions) {
        Py_DECREF(issued);
        return NULL;
    }
    for (size_t i = 0; i < info.permissions.count; ++i) {
        PyObject* mask =
            PyLong_FromUnsignedLong(info.permissions.objects[i].permissions);
        if (!mask ||
            PyDict_SetItemString(
                restrictions, info.permissions.objects[i].object_id, mask
            ) < 0) {
            Py_XDECREF(mask);
            Py_DECREF(restrictions);
            Py_DECREF(issued);
            return NULL;
        }
        Py_DECREF(mask);
    }
    PyObject* ret = Py_BuildValue(
        "(sLOIO)", info.identity, info.not_after, issued, info.permissions.role,
        restrictions
    );
    Py_DECREF(restrictions);
    Py_DECREF(issued);
    return ret;
}

static PyMethodDef libpki_methods[] = {
    {"show", py_pki_show, METH_VARARGS, NULL},
    {"init", py_pki_init, METH_VARARGS, NULL},
    {"issue", py_pki_issue, METH_VARARGS, NULL},
    {"renew", py_pki_renew, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef libpki_module = {
    .m_base = PyModuleDef_HEAD_INIT,
    .m_name = "libpki",
    .m_doc = NULL,
    .m_size = -1,
    .m_methods = libpki_methods,
};

PyMODINIT_FUNC PyInit_libpki(void) {
    return PyModule_Create(&libpki_module);
}

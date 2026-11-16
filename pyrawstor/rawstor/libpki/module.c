#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <rawstor/pki.h>

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
    const char* name;
    unsigned long validity;
    if (!PyArg_ParseTuple(args, "ssk", &dir, &name, &validity)) {
        return NULL;
    }
    int res;
    Py_BEGIN_ALLOW_THREADS;
    res = rawstor_pki_init(dir, name, validity);
    Py_END_ALLOW_THREADS;
    if (res < 0) {
        return pki_error(res);
    }
    Py_RETURN_NONE;
}

static PyObject* py_pki_issue(PyObject* Py_UNUSED(self), PyObject* args) {
    const char* dir;
    const char* identity;
    unsigned long validity;
    const char* cert_file;
    const char* key_file;
    if (!PyArg_ParseTuple(
            args, "sskss", &dir, &identity, &validity, &cert_file, &key_file
        )) {
        return NULL;
    }
    int res;
    Py_BEGIN_ALLOW_THREADS;
    res = rawstor_pki_issue(dir, identity, validity, cert_file, key_file);
    Py_END_ALLOW_THREADS;
    if (res < 0) {
        return pki_error(res);
    }
    Py_RETURN_NONE;
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
    int res;
    Py_BEGIN_ALLOW_THREADS;
    res = rawstor_pki_renew(dir, cert_file, key_file, validity);
    Py_END_ALLOW_THREADS;
    if (res < 0) {
        return pki_error(res);
    }
    Py_RETURN_NONE;
}

static PyMethodDef libpki_methods[] = {
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

#include <rawstor.h>

#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <string.h>

PyObject* py_rawstor_initialize(PyObject* Py_UNUSED(self), PyObject* args) {
    static const char* kwlist[] = {"io_attempts",      "sessions",
                                   "so_sndtimeo",      "so_rcvtimeo",
                                   "tcp_user_timeout", NULL};

    unsigned int io_attempts = 0;
    unsigned int sessions = 0;
    unsigned int so_sndtimeo = 0;
    unsigned int so_rcvtimeo = 0;
    unsigned int tcp_user_timeout = 0;

    if (!PyArg_ParseTuple(
            args, "|IIIII", kwlist, &io_attempts, &sessions, &so_sndtimeo,
            &so_rcvtimeo, &tcp_user_timeout
        )) {
        return NULL;
    }

    struct RawstorOpts opts = {
        .io_attempts = io_attempts,
        .sessions = sessions,
        .so_sndtimeo = so_sndtimeo,
        .so_rcvtimeo = so_rcvtimeo,
        .tcp_user_timeout = tcp_user_timeout
    };

    int ret = rawstor_initialize(&opts);
    if (ret < 0) {
        PyErr_Format(
            PyExc_RuntimeError, "rawstor_initialize failed: %s", strerror(-ret)
        );
        return NULL;
    }

    Py_RETURN_NONE;
}

PyObject*
py_rawstor_terminate(PyObject* Py_UNUSED(self), PyObject* Py_UNUSED(args)) {
    rawstor_terminate();
    Py_RETURN_NONE;
}

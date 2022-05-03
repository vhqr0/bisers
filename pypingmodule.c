/* The missing bindings for socket options. */

#define PY_SSIZE_T_CLEAN

#include <Python.h>

#include <netinet/icmp6.h>

static PyObject *pyping_filter_icmp6(PyObject *self, PyObject *args) {
  int sockfd, icmp6type;
  struct icmp6_filter filter;

  if (!PyArg_ParseTuple(args, "II", &sockfd, &icmp6type))
    return NULL;

  ICMP6_FILTER_SETBLOCKALL(&filter);
  ICMP6_FILTER_SETPASS(icmp6type, &filter);
  if (setsockopt(sockfd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter,
                 sizeof(filter)) < 0)
    return PyErr_SetFromErrno(PyExc_OSError);

  Py_RETURN_NONE;
}

static PyMethodDef PypingMethods[] = {
    {"filter_icmp6", pyping_filter_icmp6, METH_VARARGS, ""},
    {NULL, NULL, 0, NULL}};

static PyModuleDef pypingmodule = {PyModuleDef_HEAD_INIT, "pyping", NULL, -1,
                                   PypingMethods};

PyMODINIT_FUNC PyInit_pyping() { return PyModule_Create(&pypingmodule); }

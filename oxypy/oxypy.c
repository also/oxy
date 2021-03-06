#include <Python.h>

#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include "../oxy.h"

static int g_socket = -1;
static PyObject * g_socket_error;

static int ctl_connect() {
  struct ctl_info ctl_info;
  struct sockaddr_ctl sc;

  if (g_socket >= 0) {
    return -1;
  }

  g_socket = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
  if (g_socket < 0) {
    return -1;
  }
  bzero(&ctl_info, sizeof(struct ctl_info));
  strcpy(ctl_info.ctl_name, OXY_BUNDLEID);
  if (ioctl(g_socket, CTLIOCGINFO, &ctl_info) == -1) {
    return -1;
  }

  bzero(&sc, sizeof(struct sockaddr_ctl));
  sc.sc_len = sizeof(struct sockaddr_ctl);
  sc.sc_family = AF_SYSTEM;
  sc.ss_sysaddr = SYSPROTO_CONTROL;
  sc.sc_id = ctl_info.ctl_id;
  sc.sc_unit = 0;

  if (connect(g_socket, (struct sockaddr *)&sc, sizeof(struct sockaddr_ctl))) {
    return -1;
  }
  return 0;
}

static PyObject * oxypy_connect(PyObject *self, PyObject *args) {
  ssize_t result;
  Py_BEGIN_ALLOW_THREADS
  result = ctl_connect();
  Py_END_ALLOW_THREADS

  if (result) {
    return PyErr_SetFromErrno(g_socket_error);
  }
  else {
    Py_INCREF(Py_None);
    return Py_None;
  }
}

static PyObject * oxypy_recv(PyObject *self, PyObject *args) {
  struct outbound_connection msg;
  ssize_t result;

  Py_BEGIN_ALLOW_THREADS
  result = recv(g_socket, &msg, sizeof(msg), 0);
  Py_END_ALLOW_THREADS

  if (result < 0) {
    return PyErr_SetFromErrno(g_socket_error);
  }
  else if (result != sizeof(msg)) {
    // TODO this is a problem
    Py_INCREF(Py_None);
    return Py_None;
  }
  else {
    return Py_BuildValue("kiIH", msg.cookie, msg.pid, msg.host, msg.port);
  }
}

static PyObject * oxypy_send(PyObject *self, PyObject *args) {
  struct outbound_connection msg;
  if (!PyArg_ParseTuple(args, "kiIH", &msg.cookie, &msg.flags, &msg.host, &msg.port)) {
    return NULL;
  }
  else {
    ssize_t result;
    Py_BEGIN_ALLOW_THREADS
    result = send(g_socket, &msg, sizeof(msg), 0);
    Py_END_ALLOW_THREADS

    if (result < 0) {
      return PyErr_SetFromErrno(g_socket_error);
    }
    else {
      // FIXME ensure all bytes were sent
      Py_INCREF(Py_None);
      return Py_None;
    }
  }
}

static PyObject * oxypy_close(PyObject *self, PyObject *args) {
  int result;
  Py_BEGIN_ALLOW_THREADS
  result = close(g_socket);
  Py_END_ALLOW_THREADS

  g_socket = -1;
  if (result) {
    return PyErr_SetFromErrno(g_socket_error);
  }
  Py_INCREF(Py_None);
  return Py_None;
}

static PyMethodDef OxyMethods[] = {
  {"connect",  oxypy_connect, METH_NOARGS, "Connects to Oxy."},
  {"send",  oxypy_send, METH_VARARGS, "Send a message to Oxy."},
  {"recv",  oxypy_recv, METH_NOARGS, "Receive a message from Oxy."},
  {"close",  oxypy_close, METH_NOARGS, "Closes connection to Oxy."},

  {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyMODINIT_FUNC init_oxypy(void) {
  PyObject *m;

  PyObject *socket_module = PyImport_ImportModule("socket");
  if (!socket_module)
    return;

  g_socket_error = PyObject_GetAttrString(socket_module, "error");
  if (!g_socket_error)
    return;
  // TODO Py_DECREF socket_module?

  m = Py_InitModule("_oxypy", OxyMethods);
  if (m == NULL)
    return;
  PyModule_AddIntConstant(m, "CONNECTION_IGNORE", OXY_CONNECTION_IGNORE);
  PyModule_AddIntConstant(m, "CONNECTION_REJECT", OXY_CONNECTION_REJECT);
  PyModule_AddIntConstant(m, "CONNECTION_MODIFY", OXY_CONNECTION_MODIFY);
}


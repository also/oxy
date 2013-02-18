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

static int ctl_connect() {
  struct ctl_info ctl_info;
  struct sockaddr_ctl sc;

  if (g_socket >= 0) {
    return -1;
  }

  g_socket = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
  if (g_socket < 0) {
    perror("socket SYSPROTO_CONTROL");
    return -1;
  }
  bzero(&ctl_info, sizeof(struct ctl_info));
  strcpy(ctl_info.ctl_name, OXY_BUNDLEID);
  if (ioctl(g_socket, CTLIOCGINFO, &ctl_info) == -1) {
    perror("ioctl CTLIOCGINFO");
    return -1;
  }
    
  bzero(&sc, sizeof(struct sockaddr_ctl));
  sc.sc_len = sizeof(struct sockaddr_ctl);
  sc.sc_family = AF_SYSTEM;
  sc.ss_sysaddr = SYSPROTO_CONTROL;
  sc.sc_id = ctl_info.ctl_id;
  sc.sc_unit = 0;

  if (connect(g_socket, (struct sockaddr *)&sc, sizeof(struct sockaddr_ctl))) {
    perror("connect");
    return -1;
  }
  return 0;
}

static PyObject * oxypy_connect(PyObject *self, PyObject *args) {
  return Py_BuildValue("i", ctl_connect());
}

static PyObject * oxypy_recv(PyObject *self, PyObject *args) {
  struct outbound_connection msg;

  if (recv(g_socket, &msg, sizeof(msg), 0) != sizeof(msg)) {
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
    int result = send(g_socket, &msg, sizeof(msg), 0);
    return Py_BuildValue("i", result);
  }
}

static PyObject * oxypy_close(PyObject *self, PyObject *args) {
  int result;
  if (g_socket < 0) {
    result = -1;
  }
  else {
    result = close(g_socket);
    g_socket = -1;
  }
  return Py_BuildValue("i", result);
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

  m = Py_InitModule("_oxypy", OxyMethods);
  if (m == NULL)
      return;
  PyModule_AddIntConstant(m, "CONNECTION_IGNORE", OXY_CONNECTION_IGNORE);
  PyModule_AddIntConstant(m, "CONNECTION_REJECT", OXY_CONNECTION_REJECT);
  PyModule_AddIntConstant(m, "CONNECTION_MODIFY", OXY_CONNECTION_MODIFY);
}


#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>

#define CONTROL_SOCKET_NAME "supervisor-notify-socket"
#define NOTIFY_SOCKET_NAME "NOTIFY_SOCKET"
#define MODULE_NAME "notify"
#define RECEIVE_BUFFER_SIZE 2048

#if __linux__

static PyObject *NotifySocketError;

static PyObject *init_control_socket(PyObject *self, PyObject *args)
{
	/* create socket */
	int controlfd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (controlfd == -1) goto fail_errno;

	/* construct the address; sd_notify() requires that the path is absolute */
	struct sockaddr_un server_addr = {0};
	server_addr.sun_family = AF_UNIX;
	const size_t cwd_max = sizeof(server_addr) - offsetof(struct sockaddr_un, sun_path)
		/* but we also need space for making the path longer: */
		- 1/*slash*/ - strlen(CONTROL_SOCKET_NAME);
	if (!getcwd(server_addr.sun_path, cwd_max))
		goto fail_errno;
	char *p = server_addr.sun_path + strlen(server_addr.sun_path);
	*p = '/';
	strcpy(p + 1, CONTROL_SOCKET_NAME);

	/* overwrite the (pseudo-)file if it exists */
	(void)unlink(CONTROL_SOCKET_NAME);
	int res = bind(controlfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
	if (res < 0) goto fail_errno;

	/* make sure that we get credentials with messages */
	int data = (int)true;
	res = setsockopt(controlfd, SOL_SOCKET, SO_PASSCRED, &data, sizeof(data));
	if (res < 0) goto fail_errno;
	/* store the name of the socket in env to fake systemd */
	char *old_value = getenv(NOTIFY_SOCKET_NAME);
	if (old_value != NULL) {
		printf("[notify_socket] warning, running under systemd and overwriting $%s\n",
		       NOTIFY_SOCKET_NAME);
		// fixme
	}

	res = setenv(NOTIFY_SOCKET_NAME, server_addr.sun_path, 1);
	if (res < 0) goto fail_errno;

	return PyLong_FromLong((long)controlfd);
fail_errno:
	PyErr_SetFromErrno(NotifySocketError);
	return NULL;
}

static PyObject *handle_control_socket_connection_event(PyObject *self,
							PyObject *args)
{
	long controlfd;
	if (!PyArg_ParseTuple(args, "i", &controlfd))
		return NULL;

	/* read command assuming it fits and it was sent all at once */
	// prepare space to read filedescriptors
	struct msghdr msg;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;

	// prepare a place to read the actual message
	char place_for_data[RECEIVE_BUFFER_SIZE];
	bzero(&place_for_data, sizeof(place_for_data));
	struct iovec iov = { .iov_base = &place_for_data,
			     .iov_len = sizeof(place_for_data) };
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	char cmsg[CMSG_SPACE(sizeof(struct ucred))];
	msg.msg_control = cmsg;
	msg.msg_controllen = sizeof(cmsg);

	/* Receive real plus ancillary data */
	int len = recvmsg(controlfd, &msg, 0);
	if (len == -1) {
		if (errno == EWOULDBLOCK || errno == EAGAIN) {
			Py_RETURN_NONE;
		} else {
			PyErr_SetFromErrno(NotifySocketError);
			return NULL;
		}
	}

	/* read the sender pid */
	struct cmsghdr *cmsgp = CMSG_FIRSTHDR(&msg);
	pid_t pid = -1;
	while (cmsgp != NULL) {
		if (cmsgp->cmsg_type == SCM_CREDENTIALS) {
		    if (
		    	cmsgp->cmsg_len != CMSG_LEN(sizeof(struct ucred)) ||
		    	cmsgp->cmsg_level != SOL_SOCKET
		    ) {
		    	printf("[notify_socket] invalid cmsg data, ignoring\n");
		    	Py_RETURN_NONE;
		    }

			struct ucred cred;
			memcpy(&cred, CMSG_DATA(cmsgp), sizeof(cred));
			pid = cred.pid;
		}
		cmsgp = CMSG_NXTHDR(&msg, cmsgp);
	}
	if (pid == -1) {
		printf("[notify_socket] ignoring received data without credentials: %s\n",
		       place_for_data);
		Py_RETURN_NONE;
	}

	/* return received data as a tuple (pid, data bytes) */
	return Py_BuildValue("iy", pid, place_for_data);
}

static PyMethodDef NotifyMethods[] = {
	{ "init_socket", init_control_socket, METH_VARARGS,
	  "Init notify socket. Returns it's file descriptor." },
	{ "read_message", handle_control_socket_connection_event, METH_VARARGS,
	  "Reads datagram from notify socket. Returns tuple of PID and received bytes." },
	{ NULL, NULL, 0, NULL } /* Sentinel */
};

static struct PyModuleDef notifymodule = {
	PyModuleDef_HEAD_INIT, MODULE_NAME, /* name of module */
	NULL, /* module documentation, may be NULL */
	-1, /* size of per-interpreter state of the module,
           or -1 if the module keeps state in global variables. */
	NotifyMethods
};

PyMODINIT_FUNC PyInit_notify(void)
{
	PyObject *m;

	m = PyModule_Create(&notifymodule);
	if (m == NULL)
		return NULL;

	NotifySocketError =
		PyErr_NewException(MODULE_NAME ".error", NULL, NULL);
	Py_XINCREF(NotifySocketError);
	if (PyModule_AddObject(m, "error", NotifySocketError) < 0) {
		Py_XDECREF(NotifySocketError);
		Py_CLEAR(NotifySocketError);
		Py_DECREF(m);
		return NULL;
	}

	return m;
}

#endif

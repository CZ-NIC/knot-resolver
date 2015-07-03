/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <pthread.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <fcntl.h>

#include <libknot/descriptor.h>
#include <libknot/packet/pkt.h>
#include <libknot/internal/net.h>

#include <Python.h>


/*
 * Globals
 */
#ifdef __APPLE__
    #define MOCK__TZ_ARG void
    #define MOCK__SOCKADDR_ARG struct sockaddr *restrict
    #define MOCK__CONST_SOCKADDR_ARG const struct sockaddr *
    #define MOCK__GET_SOCKADDR(arg) arg
    #define errno_location __error()
#else
    #define MOCK__TZ_ARG struct timezone
    #define MOCK__SOCKADDR_ARG __SOCKADDR_ARG
    #define MOCK__CONST_SOCKADDR_ARG __CONST_SOCKADDR_ARG
    #define MOCK__GET_SOCKADDR(arg) arg.__sockaddr__
    #define errno_location __errno_location()
#endif

struct timeval g_mock_time;        /* Mocked system time */
PyObject *g_mock_server  = NULL;   /* Mocked endpoint for recursive queries */

struct sockaddr_storage original_dst = { 0 };
int original_dst_len = 0;
int connected_fd = -1;

int (*original_connect)(int __fd, MOCK__CONST_SOCKADDR_ARG __addr,
                        socklen_t __len) = NULL;

ssize_t (*original_recvfrom) (int __fd, void *__restrict __buf, size_t __n,
                              int __flags, MOCK__SOCKADDR_ARG __addr,
                              socklen_t *__restrict __addr_len) = NULL;

ssize_t (*original_recv) (int __fd, void *__buf,
                          size_t __n, int __flags) = NULL;

int (*original_select) (int __nfds, fd_set *__restrict __readfds,
                        fd_set *__restrict __writefds,
                        fd_set *__restrict __exceptfds,
                        struct timeval *__restrict __timeout) = NULL;

#define FIND_ORIGINAL(fname) \
	if (original_##fname == NULL) \
	{ \
		original_##fname = dlsym(RTLD_NEXT,#fname); \
		assert(original_##fname); \
	}

int gettimeofday(struct timeval *tv, MOCK__TZ_ARG *tz)
{
	memcpy(tv, &g_mock_time, sizeof(struct timeval));
	return 0;
}

ssize_t recvfrom (int __fd, void *__restrict __buf, size_t __n,
			 int __flags, MOCK__SOCKADDR_ARG __addr,
			 socklen_t *__restrict __addr_len)
{
	ssize_t ret = -1;
	struct sockaddr *addr = MOCK__GET_SOCKADDR(__addr);
	FIND_ORIGINAL(recvfrom);
	if (__fd == connected_fd) {
		/* May block, must unlock GIL */
		if ((__flags & MSG_DONTWAIT) == 0) {
			Py_BEGIN_ALLOW_THREADS
			ret = original_recvfrom( __fd,__buf,__n,__flags,__addr,__addr_len);
			Py_END_ALLOW_THREADS
		} else {
			ret = original_recvfrom( __fd,__buf,__n,__flags,__addr,__addr_len);
		}
		if (addr != NULL && *__addr_len > 0) {
		    int len = original_dst_len;
		    if (len < *__addr_len)
			len = *__addr_len;
		    memcpy(addr, &original_dst, len);
		}
	} else {
		ret = original_recvfrom( __fd,__buf,__n,__flags,__addr,__addr_len);
	}
	return ret;
}

ssize_t recv (int __fd, void *__buf, size_t __n, int __flags)
{
	ssize_t ret;
	FIND_ORIGINAL(recv);
	if (__fd == connected_fd) {
		/* May block, must unlock GIL */
		if ((__flags & MSG_DONTWAIT) == 0) {
	                Py_BEGIN_ALLOW_THREADS
			ret = original_recv (__fd,__buf,__n,__flags);
			Py_END_ALLOW_THREADS
		} else{
			ret = original_recv (__fd,__buf,__n,__flags);
		}
	} else {
		ret = original_recv (__fd,__buf,__n,__flags);
	}
	return ret;
}

int select (int __nfds, fd_set *__restrict __readfds,
			fd_set *__restrict __writefds,
			fd_set *__restrict __exceptfds,
			struct timeval *__restrict __timeout)
{
	int ret;
	FIND_ORIGINAL(select);
	if (connected_fd != -1 && __nfds > connected_fd && (
		(__readfds   != NULL && FD_ISSET(connected_fd, __readfds))  ||
		(__writefds  != NULL && FD_ISSET(connected_fd, __writefds)) ||
		(__exceptfds != NULL && FD_ISSET(connected_fd, __exceptfds))
	    )) {
		struct timeval _timeout = {0, 200 * 1000};
		Py_BEGIN_ALLOW_THREADS
		ret = original_select (__nfds,
			__readfds,__writefds,__exceptfds,&_timeout);
		Py_END_ALLOW_THREADS
	} else {
		ret = original_select (__nfds,
			__readfds,__writefds,__exceptfds,__timeout);
	}
	return ret;
}

int connect(int __fd, MOCK__CONST_SOCKADDR_ARG __addr, socklen_t __len)
{
	Dl_info dli = {0};
	char *python_addr = NULL;
	struct addrinfo hints;
	struct addrinfo *info = NULL;
	int ret, parse_ret, python_port = 0, flowinfo, scopeid, local_socktype;
	socklen_t local_socktypelen = sizeof(int);
	const struct sockaddr *dst_addr = MOCK__GET_SOCKADDR(__addr);
	char right_caller[] = "net_connected_socket";
	PyObject *result = NULL;
	char addr_str[SOCKADDR_STRLEN];
	char pport[32];

	/* @note This is only going to work if we're calling from a function which has a
	         symbol in the symbol table, must link dynamically. */
	FIND_ORIGINAL(connect);
	dladdr (__builtin_return_address (0), &dli);
	if (!dli.dli_sname ||
		(strncmp(right_caller,dli.dli_sname,strlen(right_caller)) != 0))
	    return original_connect (__fd, __addr, __len);

	sockaddr_tostr(addr_str, SOCKADDR_STRLEN,
		(const struct sockaddr_storage *)dst_addr);

	if (dst_addr->sa_family != AF_INET && dst_addr->sa_family != AF_INET6) {
	    errno = EINVAL;
	    return -1;
	}

	getsockopt(__fd, SOL_SOCKET, SO_TYPE,
			&local_socktype, &local_socktypelen);

	if (local_socktype == SOCK_DGRAM) {
		result = PyObject_CallMethod(g_mock_server, "get_server_socket",
					"si", addr_str, dst_addr->sa_family);
		if (result == NULL) {
			errno = ECONNABORTED;
			return -1;
		}
	} else {
		errno = EINVAL;
		return -1;
	}

	if (dst_addr->sa_family == AF_INET) {
		parse_ret = PyArg_ParseTuple(result, "si",
				&python_addr, &python_port);
	} else {
		parse_ret = PyArg_ParseTuple(result, "siii",
				&python_addr, &python_port, &flowinfo, &scopeid);
	}

	Py_DECREF(result);

	if (!parse_ret) {
		errno = ECONNABORTED;
		return -1;
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = dst_addr->sa_family;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = IPPROTO_UDP;
	sprintf (pport,"%i",python_port);
	ret = getaddrinfo(python_addr,pport,&hints,&info);
	if (ret) {
		errno = ECONNABORTED;
		return -1;
	}

	connected_fd = __fd;
	ret = original_connect (__fd, info->ai_addr, info->ai_addrlen);
	freeaddrinfo(info);
	memcpy(&original_dst,dst_addr,__len);
	original_dst_len = __len;
	return ret;
}


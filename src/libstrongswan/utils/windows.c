/*
 * Copyright (C) 2013 Martin Willi
 * Copyright (C) 2013 revosec AG
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "utils.h"

#include <errno.h>

/**
 * See header
 */
void windows_init()
{
	WSADATA wsad;

	/* initialize winsock2 */
	WSAStartup(MAKEWORD(2, 2), &wsad);
}

/**
 * See header
 */
void windows_deinit()
{
	WSACleanup();
}

/**
 * See header
 */
int usleep(useconds_t usec)
{
	if (usec > 0 && usec < 1000)
	{	/* do not Sleep(0) for small values */
		usec = 1000;
	}
	SleepEx(usec / 1000, TRUE);
	return 0;
}

/**
 * See header
 */
int socketpair(int domain, int type, int protocol, int sv[2])
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	socklen_t len = sizeof(addr);
	int s, c, sc;
	BOOL on;

	/* We don't check domain for AF_INET, as we use it as replacement for
	 * AF_UNIX. */
	if (type != SOCK_STREAM)
	{
		errno = EINVAL;
		return -1;
	}
	if (protocol != 0 && protocol != IPPROTO_TCP)
	{
		errno = EINVAL;
		return -1;
	}
	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == -1)
	{
		return -1;
	}
	c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (c == -1)
	{
		closesocket(c);
		return -1;
	}
	if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) == 0 &&
		getsockname(s,(struct sockaddr*)&addr, &len) == 0 &&
		listen(s, 0) == 0 &&
		connect(c, (struct sockaddr*)&addr, sizeof(addr)) == 0)
	{
		sc = accept(s, NULL, NULL);
		if (sc > 0)
		{
			closesocket(s);
			s = sc;
			if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY,
						   (void*)&on, sizeof(on)) == 0 &&
				setsockopt(c, IPPROTO_TCP, TCP_NODELAY,
						   (void*)&on, sizeof(on)) == 0)
			{
				sv[0] = s;
				sv[1] = c;
				return 0;
			}
		}
	}
	closesocket(s);
	closesocket(c);
	return -1;
}

/**
 * Set errno for a function setting WSA error on failure
 */
static int wserr(int retval)
{
	if (retval < 0)
	{
		switch (WSAGetLastError())
		{
			case WSANOTINITIALISED:
				errno = EBADF;
				break;
			case WSAENETDOWN:
			case WSAENETRESET:
			case WSAESHUTDOWN:
				errno = EPIPE;
				break;
			case WSAEACCES:
				errno = EACCES;
				break;
			case WSAEINTR:
				errno = EINTR;
				break;
			case WSAEINPROGRESS:
				errno = EBUSY;
				break;
			case WSAEFAULT:
				errno = EFAULT;
				break;
			case WSAENOBUFS:
				errno = ENOMEM;
				break;
			case WSAENOTSOCK:
				errno = EINVAL;
				break;
			case WSAEOPNOTSUPP:
				errno = ENOSYS;
				break;
			case WSAEWOULDBLOCK:
				errno = EWOULDBLOCK;
				break;
			case WSAEMSGSIZE:
				errno = ENOSPC;
				break;
			case WSAEINVAL:
				errno = EINVAL;
				break;
			case WSAENOTCONN:
			case WSAEHOSTUNREACH:
			case WSAECONNABORTED:
			case WSAECONNRESET:
				errno = EIO;
				break;
			case WSAETIMEDOUT:
				errno = ESRCH;
				break;
			default:
				errno = ENOENT;
				break;
		}
	}
	else
	{
		errno = 0;
	}
	return retval;
}

/**
 * Check and clear the dontwait flag
 */
static bool check_dontwait(int *flags)
{
	if (*flags & MSG_DONTWAIT)
	{
		*flags &= ~MSG_DONTWAIT;
		return TRUE;
	}
	return FALSE;
}

/**
 * See header
 */
#undef recv
ssize_t windows_recv(int sockfd, void *buf, size_t len, int flags)
{
	u_long on = 1, off = 0;
	ssize_t outlen = -1;

	if (!check_dontwait(&flags))
	{
		return wserr(recv(sockfd, buf, len, flags));
	}
	if (wserr(ioctlsocket(sockfd, FIONBIO, &on) == 0))
	{
		outlen = wserr(recv(sockfd, buf, len, flags));
		ioctlsocket(sockfd, FIONBIO, &off);
	}
	return outlen;
}

/**
 * See header
 */
#undef recvfrom
ssize_t windows_recvfrom(int sockfd, void *buf, size_t len, int flags,
						 struct sockaddr *src_addr, socklen_t *addrlen)
{
	u_long on = 1, off = 0;
	ssize_t outlen = -1;

	if (!check_dontwait(&flags))
	{
		return wserr(recvfrom(sockfd, buf, len, flags, src_addr, addrlen));
	}
	if (wserr(ioctlsocket(sockfd, FIONBIO, &on)) == 0)
	{
		outlen = wserr(recvfrom(sockfd, buf, len, flags, src_addr, addrlen));
		ioctlsocket(sockfd, FIONBIO, &off);
	}
	return outlen;
}

/**
 * See header
 */
#undef send
ssize_t windows_send(int sockfd, const void *buf, size_t len, int flags)
{
	u_long on = 1, off = 0;
	ssize_t outlen = -1;

	if (!check_dontwait(&flags))
	{
		return wserr(send(sockfd, buf, len, flags));
	}
	if (wserr(ioctlsocket(sockfd, FIONBIO, &on)) == 0)
	{
		outlen = wserr(send(sockfd, buf, len, flags));
		ioctlsocket(sockfd, FIONBIO, &off);
	}
	return outlen;
}

/**
 * See header
 */
#undef sendto
ssize_t windows_sendto(int sockfd, const void *buf, size_t len, int flags,
					   const struct sockaddr *dest_addr, socklen_t addrlen)
{
	u_long on = 1, off = 0;
	ssize_t outlen = -1;

	if (!check_dontwait(&flags))
	{
		return wserr(sendto(sockfd, buf, len, flags, dest_addr, addrlen));
	}
	if (wserr(ioctlsocket(sockfd, FIONBIO, &on)) == 0)
	{
		outlen = wserr(sendto(sockfd, buf, len, flags, dest_addr, addrlen));
		ioctlsocket(sockfd, FIONBIO, &off);
	}
	return outlen;
}

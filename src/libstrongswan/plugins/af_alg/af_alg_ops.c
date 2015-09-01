/*
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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

#include "af_alg_ops.h"

#include <unistd.h>
#include <errno.h>
#include <linux/socket.h>

#include <utils/debug.h>

/* added with Linux 3.19 */
#ifndef ALG_SET_AEAD_ASSOCLEN
#define ALG_SET_AEAD_ASSOCLEN 4
#endif

#ifndef ALG_SET_AEAD_AUTHSIZE
#define ALG_SET_AEAD_AUTHSIZE 5
#endif

typedef struct private_af_alg_ops_t private_af_alg_ops_t;

/**
 * Private data of an af_alg_ops_t object.
 */
struct private_af_alg_ops_t {

	/**
	 * Public af_alg_ops_t interface.
	 */
	af_alg_ops_t public;

	/**
	 * Transform FD
	 */
	int tfm;

	/**
	 * Operation FD
	 */
	int op;
};

METHOD(af_alg_ops_t, reset, void,
	private_af_alg_ops_t *this)
{
	if (this->op != -1)
	{
		close(this->op);
		this->op = -1;
	}
}

METHOD(af_alg_ops_t, hash, bool,
	private_af_alg_ops_t *this, chunk_t data, char *out, size_t outlen)
{
	ssize_t len;

	while (this->op == -1)
	{
		this->op = accept(this->tfm, NULL, 0);
		if (this->op == -1 && errno != EINTR)
		{
			DBG1(DBG_LIB, "opening AF_ALG hasher failed: %s", strerror(errno));
			return FALSE;
		}
	}

	do
	{
		len = send(this->op, data.ptr, data.len, out ? 0 : MSG_MORE);
		if (len == -1)
		{
			if (errno == EINTR)
			{
				continue;
			}
			DBG1(DBG_LIB, "writing to AF_ALG hasher failed: %s", strerror(errno));
			return FALSE;
		}
		data = chunk_skip(data, len);
	}
	while (data.len);

	if (out)
	{
		while (outlen)
		{
			len = read(this->op, out, outlen);
			if (len == -1)
			{
				if (errno == EINTR)
				{
					continue;
				}
				DBG1(DBG_LIB, "reading AF_ALG hasher failed: %s", strerror(errno));
				return FALSE;
			}
			outlen -= len;
			out += len;
		}
		reset(this);
	}
	return TRUE;
}

METHOD(af_alg_ops_t, crypt, bool,
	private_af_alg_ops_t *this, u_int32_t type, chunk_t iv, chunk_t data,
	char *out)
{
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	struct af_alg_iv *ivm;
	struct iovec iov;
	char buf[CMSG_SPACE(sizeof(type)) +
			 CMSG_SPACE(offsetof(struct af_alg_iv, iv) + iv.len)];
	ssize_t len;
	int op;

	do
	{
		op = accept(this->tfm, NULL, 0);
		if (op == -1 && errno != EINTR)
		{
			DBG1(DBG_LIB, "accepting AF_ALG crypter failed: %s", strerror(errno));
			return FALSE;
		}
	}
	while (op == -1);

	memset(buf, 0, sizeof(buf));

	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(sizeof(type));
	memcpy(CMSG_DATA(cmsg), &type, sizeof(type));

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(offsetof(struct af_alg_iv, iv) + iv.len);
	ivm = (void*)CMSG_DATA(cmsg);
	ivm->ivlen = iv.len;
	memcpy(ivm->iv, iv.ptr, iv.len);

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	while (data.len)
	{
		iov.iov_base = data.ptr;
		iov.iov_len = data.len;

		len = sendmsg(op, &msg, 0);
		if (len == -1)
		{
			if (errno == EINTR)
			{
				continue;
			}
			DBG1(DBG_LIB, "writing to AF_ALG crypter failed: %s", strerror(errno));
			close(op);
			return FALSE;
		}
		while (read(op, out, len) != len)
		{
			if (errno != EINTR)
			{
				DBG1(DBG_LIB, "reading from AF_ALG crypter failed: %s",
					 strerror(errno));
				close(op);
				return FALSE;
			}
		}
		data = chunk_skip(data, len);
		/* no IV for subsequent data chunks */
		msg.msg_controllen = 0;
	}
	close(op);
	return TRUE;
}

METHOD(af_alg_ops_t, crypt_aead, bool,
	private_af_alg_ops_t *this, u_int32_t type, chunk_t iv, chunk_t data,
	chunk_t assoc, size_t icv, chunk_t out)
{
	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	struct af_alg_iv *ivm;
	struct iovec iov[3];
	u_int32_t assoclen = assoc.len;
	char buf[CMSG_SPACE(sizeof(type)) +
			 CMSG_SPACE(offsetof(struct af_alg_iv, iv) + iv.len) +
			 (assoclen ? CMSG_SPACE(sizeof(assoclen)) : 0)];
	char assocbuf[assoclen];
	int op;

	do
	{
		op = accept(this->tfm, NULL, 0);
		if (op == -1 && errno != EINTR)
		{
			DBG1(DBG_LIB, "accepting AF_ALG socket failed: %s", strerror(errno));
			return FALSE;
		}
	}
	while (op == -1);

	memset(buf, 0, sizeof(buf));

	/* The interface added with Linux 4.3 is a bit strange, it requires us to
	 * pass the same amount of memory in the request and the response.  So while
	 * we don't expect an ICV when decrypting or any AAD in either operation, we
	 * still have to pass memory down to the kernel when getting the results.
	 * The problem thereby is that the kernel does some checks when getting the
	 * iovecs and will fail with an EFAULT when the target is not writable (even
	 * though the kernel might not actually touch that area).  For instance, we
	 * can't just pass the original ICV when decrypting from static data as used
	 * in the test vectors. */

	msg.msg_control = buf;
	msg.msg_controllen = sizeof(buf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(sizeof(type));
	memcpy(CMSG_DATA(cmsg), &type, sizeof(type));

	cmsg = CMSG_NXTHDR(&msg, cmsg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;
	cmsg->cmsg_len = CMSG_LEN(offsetof(struct af_alg_iv, iv) + iv.len);
	ivm = (void*)CMSG_DATA(cmsg);
	ivm->ivlen = iv.len;
	memcpy(ivm->iv, iv.ptr, iv.len);

	if (assoclen)
	{
		cmsg = CMSG_NXTHDR(&msg, cmsg);
		cmsg->cmsg_level = SOL_ALG;
		cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
		cmsg->cmsg_len = CMSG_LEN(sizeof(assoclen));
		memcpy(CMSG_DATA(cmsg), &assoclen, sizeof(assoclen));
	}

	msg.msg_iov = iov;
	if (assoclen)
	{
		iov[msg.msg_iovlen].iov_base = assoc.ptr;
		iov[msg.msg_iovlen].iov_len = assoclen;
		msg.msg_iovlen++;
	}
	if (data.len)
	{
		iov[msg.msg_iovlen].iov_base = data.ptr;
		iov[msg.msg_iovlen].iov_len = data.len;
		msg.msg_iovlen++;
	}
	/* As described above even when encrypting we need to pass this because the
	 * kernel expects the same amount of memory in both calls, however, data.ptr
	 * might be NULL when encrypting, so we pass the same pointer as below when
	 * retrieving the actual ICV */
	if (type == ALG_OP_ENCRYPT)
	{
		iov[msg.msg_iovlen].iov_base = out.ptr + out.len;
	}
	else
	{
		iov[msg.msg_iovlen].iov_base = data.ptr + data.len;
	}
	iov[msg.msg_iovlen].iov_len = icv;
	msg.msg_iovlen++;

	while (sendmsg(op, &msg, 0) == -1)
	{
		if (errno != EINTR)
		{
			DBG1(DBG_LIB, "writing to AF_ALG socket failed: %s",
				 strerror(errno));
			close(op);
			return FALSE;
		}
	}

	msg.msg_controllen = 0;
	msg.msg_iovlen = 0;

	/* Again, we don't expect any AAD back from the kernel, but the interface
	 * requires us to pass the same memory as above and since it must be
	 * writable, which assoc.ptr might not be, we use a dummy buffer of the
	 * same size */
	if (assoclen)
	{
		iov[msg.msg_iovlen].iov_base = assocbuf;
		iov[msg.msg_iovlen].iov_len = assoclen;
		msg.msg_iovlen++;
	}
	if (out.len)
	{
		iov[msg.msg_iovlen].iov_base = out.ptr;
		iov[msg.msg_iovlen].iov_len = out.len;
		msg.msg_iovlen++;
	}
	iov[msg.msg_iovlen].iov_base = out.ptr + out.len;
	iov[msg.msg_iovlen].iov_len = icv;
	msg.msg_iovlen++;

	while (recvmsg(op, &msg, 0) == -1)
	{
		if (errno != EINTR)
		{
			DBG1(DBG_LIB, "reading from AF_ALG socket failed: %s",
				 strerror(errno));
			close(op);
			return FALSE;
		}
	}
	close(op);
	return TRUE;
}

METHOD(af_alg_ops_t, set_key, bool,
	private_af_alg_ops_t *this, chunk_t key)
{
	if (setsockopt(this->tfm, SOL_ALG, ALG_SET_KEY, key.ptr, key.len) == -1)
	{
		DBG1(DBG_LIB, "setting AF_ALG key failed: %s", strerror(errno));
		return FALSE;
	}
	return TRUE;
}

METHOD(af_alg_ops_t, set_icv_length, bool,
	private_af_alg_ops_t *this, size_t len)
{
	if (setsockopt(this->tfm, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, len) == -1)
	{
		DBG1(DBG_LIB, "setting AF_ALG ICV length failed: %s", strerror(errno));
		return FALSE;
	}
	return TRUE;
}

METHOD(af_alg_ops_t, destroy, void,
	private_af_alg_ops_t *this)
{
	close(this->tfm);
	if (this->op != -1)
	{
		close(this->op);
	}
	free(this);
}

/**
 * See header
 */
af_alg_ops_t *af_alg_ops_create(char *type, char *alg)
{
	private_af_alg_ops_t *this;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
	};

	strncpy(sa.salg_type, type, sizeof(sa.salg_type));
	strncpy(sa.salg_name, alg, sizeof(sa.salg_name));

	INIT(this,
		.public = {
			.hash = _hash,
			.reset = _reset,
			.crypt = _crypt,
			.crypt_aead = _crypt_aead,
			.set_key = _set_key,
			.set_icv_length = _set_icv_length,
			.destroy = _destroy,
		},
		.tfm = socket(AF_ALG, SOCK_SEQPACKET, 0),
		.op = -1,
	);
	if (this->tfm == -1)
	{
		DBG1(DBG_LIB, "opening AF_ALG socket failed: %s", strerror(errno));
		free(this);
		return NULL;
	}
	if (bind(this->tfm, (struct sockaddr*)&sa, sizeof(sa)) == -1)
	{
		if (errno != ENOENT)
		{	/* fail silently if algorithm not supported */
			DBG1(DBG_LIB, "binding AF_ALG socket for '%s' failed: %s",
				 sa.salg_name, strerror(errno));
		}
		destroy(this);
		return NULL;
	}
	return &this->public;
}

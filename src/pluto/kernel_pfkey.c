/*
 * Copyright (C) 2010 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
 * Copyright (C) 2003 Herbert Xu.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 1997 Angelos D. Keromytis.
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

#include <errno.h>
#include <unistd.h>

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <freeswan.h>
#include <pfkeyv2.h>
#include <pfkey.h>

#include "constants.h"
#include "kernel.h"
#include "kernel_pfkey.h"
#include "log.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */
#include "kernel_alg.h"


static int pfkeyfd = NULL_FD;

typedef u_int32_t pfkey_seq_t;
static pfkey_seq_t pfkey_seq = 0; /* sequence number for our PF_KEY messages */

static pid_t pid;

#define NE(x) { x, #x } /* Name Entry -- shorthand for sparse_names */

static sparse_names pfkey_type_names = {
		NE(SADB_RESERVED),
		NE(SADB_GETSPI),
		NE(SADB_UPDATE),
		NE(SADB_ADD),
		NE(SADB_DELETE),
		NE(SADB_GET),
		NE(SADB_ACQUIRE),
		NE(SADB_REGISTER),
		NE(SADB_EXPIRE),
		NE(SADB_FLUSH),
		NE(SADB_DUMP),
		NE(SADB_X_PROMISC),
		NE(SADB_X_PCHANGE),
		NE(SADB_X_GRPSA),
		NE(SADB_X_ADDFLOW),
		NE(SADB_X_DELFLOW),
		NE(SADB_X_DEBUG),
		NE(SADB_X_NAT_T_NEW_MAPPING),
		NE(SADB_MAX),
		{ 0, sparse_end }
};

#undef NE

typedef union {
		unsigned char bytes[PFKEYv2_MAX_MSGSIZE];
		struct sadb_msg msg;
	} pfkey_buf;

static bool
pfkey_input_ready(void)
{
	int ndes;
	fd_set readfds;
	struct timeval tm = { .tv_sec = 0 }; /* don't wait, polling */

	FD_ZERO(&readfds);  /* we only care about pfkeyfd */
	FD_SET(pfkeyfd, &readfds);

	do {
		ndes = select(pfkeyfd + 1, &readfds, NULL, NULL, &tm);
	} while (ndes == -1 && errno == EINTR);

	if (ndes < 0)
	{
		log_errno((e, "select() failed in pfkey_get()"));
		return FALSE;
	}
	else if (ndes == 0)
	{
		return FALSE;   /* nothing to read */
	}
	passert(ndes == 1 && FD_ISSET(pfkeyfd, &readfds));
	return TRUE;
}

/* get a PF_KEY message from kernel.
 * Returns TRUE if message found, FALSE if no message pending,
 * and aborts or keeps trying when an error is encountered.
 * The only validation of the message is that the message length
 * received matches that in the message header, and that the message
 * is for this process.
 */
static bool
pfkey_get(pfkey_buf *buf)
{
	for (;;)
	{
		/* len must be less than PFKEYv2_MAX_MSGSIZE,
		 * so it should fit in an int.  We use this fact when printing it.
		 */
		ssize_t len;

		if (!pfkey_input_ready())
		{
			return FALSE;
		}

		len = read(pfkeyfd, buf->bytes, sizeof(buf->bytes));

		if (len < 0)
		{
			if (errno == EAGAIN)
			{
				return FALSE;
			}
			log_errno((e, "read() failed in pfkey_get()"));
			return FALSE;
		}
		else if ((size_t)len < sizeof(buf->msg))
		{
			plog("pfkey_get read truncated PF_KEY message: %d bytes; ignoring",
				 (int)len);
		}
		else if ((size_t)len != buf->msg.sadb_msg_len * IPSEC_PFKEYv2_ALIGN)
		{
			plog("pfkey_get read PF_KEY message with length %d that doesn't"
				 " equal sadb_msg_len %u * %u; ignoring message", (int)len,
				 (unsigned)buf->msg.sadb_msg_len, (unsigned)IPSEC_PFKEYv2_ALIGN);
		}
		else if (buf->msg.sadb_msg_pid != (unsigned)pid)
		{
			/* not for us: ignore */
			DBG(DBG_KERNEL,
				DBG_log("pfkey_get: ignoring PF_KEY %s message %u for process"
						" %u", sparse_val_show(pfkey_type_names,
											   buf->msg.sadb_msg_type),
						buf->msg.sadb_msg_seq, buf->msg.sadb_msg_pid));
		}
		else
		{
			DBG(DBG_KERNEL,
				DBG_log("pfkey_get: %s message %u",
						sparse_val_show(pfkey_type_names,
										buf->msg.sadb_msg_type),
						buf->msg.sadb_msg_seq));
			return TRUE;
		}
	}
}

/* get a response to a specific message */
static bool
pfkey_get_response(pfkey_buf *buf, pfkey_seq_t seq)
{
	while (pfkey_get(buf))
	{
		if (buf->msg.sadb_msg_seq == seq)
		{
			return TRUE;
		}
	}
	return FALSE;
}

static bool
pfkey_build(int error, const char *description, const char *text_said,
			struct sadb_ext *extensions[SADB_EXT_MAX + 1])
{
	if (error != 0)
	{
		loglog(RC_LOG_SERIOUS, "building of %s %s failed, code %d", description,
							   text_said, error);
		pfkey_extensions_free(extensions);
		return FALSE;
	}
	return TRUE;
}

/* pfkey_extensions_init + pfkey_build + pfkey_msg_hdr_build */
static bool
pfkey_msg_start(u_int8_t msg_type, u_int8_t satype, const char *description,
				const char *text_said,
				struct sadb_ext *extensions[SADB_EXT_MAX + 1])
{
	pfkey_extensions_init(extensions);
	return pfkey_build(pfkey_msg_hdr_build(&extensions[0], msg_type, satype, 0,
										   ++pfkey_seq, pid),
					   description, text_said, extensions);
}

/* Finish (building, sending, accepting response for) PF_KEY message.
 * If response isn't NULL, the response from the kernel will be
 * placed there (and its errno field will not be examined).
 * Returns TRUE iff all appears well.
 */
static bool
finish_pfkey_msg(struct sadb_ext *extensions[SADB_EXT_MAX + 1],
				 const char *description, const char *text_said,
				 pfkey_buf *response)
{
	struct sadb_msg *pfkey_msg;
	bool success = TRUE;
	int error;

	error = pfkey_msg_build(&pfkey_msg, extensions, EXT_BITS_IN);

	if (error != 0)
	{
		loglog(RC_LOG_SERIOUS, "pfkey_msg_build of %s %s failed, code %d",
							   description, text_said, error);
		success = FALSE;
	}
	else
	{
		size_t len = pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN;

		DBG(DBG_KERNEL,
			DBG_log("finish_pfkey_msg: %s message %u for %s %s",
					sparse_val_show(pfkey_type_names, pfkey_msg->sadb_msg_type),
					pfkey_msg->sadb_msg_seq, description, text_said);
			DBG_dump(NULL, (void *) pfkey_msg, len));

		ssize_t r = write(pfkeyfd, pfkey_msg, len);

		if (r != (ssize_t)len)
		{
			if (r < 0)
			{
				log_errno((e, "pfkey write() of %s message %u for %s %s"
						  " failed", sparse_val_show(pfkey_type_names,
							pfkey_msg->sadb_msg_type), pfkey_msg->sadb_msg_seq,
						  description, text_said));
			}
			else
			{
				loglog(RC_LOG_SERIOUS, "ERROR: pfkey write() of %s message"
					   " %u for %s %s truncated: %ld instead of %ld",
					   sparse_val_show(pfkey_type_names,
							pfkey_msg->sadb_msg_type), pfkey_msg->sadb_msg_seq,
						description, text_said, (long)r, (long)len);
			}
			success = FALSE;

			/* if we were compiled with debugging, but we haven't already
			 * dumped the command, do so.
			 */
#ifdef DEBUG
			if ((cur_debugging & DBG_KERNEL) == 0)
				DBG_dump(NULL, (void *) pfkey_msg, len);
#endif
		}
		else
		{
			/* Check response from kernel.
			 * It ought to be an echo, perhaps with additional info.
			 * If the caller wants it, response will point to space.
			 */
			pfkey_buf b;
			pfkey_buf *bp = response != NULL? response : &b;

			if (!pfkey_get_response(bp,
						((struct sadb_msg *)extensions[0])->sadb_msg_seq))
			{
				loglog(RC_LOG_SERIOUS, "ERROR: no response to our PF_KEY %s"
					   " message for %s %s", sparse_val_show(pfkey_type_names,
							pfkey_msg->sadb_msg_type), description, text_said);
				success = FALSE;
			}
			else if (pfkey_msg->sadb_msg_type != bp->msg.sadb_msg_type)
			{
				loglog(RC_LOG_SERIOUS, "ERROR: response to our PF_KEY %s"
					   " message for %s %s was of wrong type (%s)",
					   sparse_name(pfkey_type_names, pfkey_msg->sadb_msg_type),
					   description, text_said, sparse_val_show(pfkey_type_names,
							bp->msg.sadb_msg_type));
				success = FALSE;
			}
			else if (response == NULL && bp->msg.sadb_msg_errno != 0)
			{
				/* Kernel is signalling a problem */
				loglog(RC_LOG_SERIOUS, "ERROR: PF_KEY %s response for %s %s"
					   " included errno %u: %s",
					   sparse_val_show(pfkey_type_names,
							pfkey_msg->sadb_msg_type), description, text_said,
					   (unsigned) bp->msg.sadb_msg_errno,
					   strerror(bp->msg.sadb_msg_errno));
				success = FALSE;
			}
		}
	}
	pfkey_extensions_free(extensions);
	pfkey_msg_free(&pfkey_msg);
	return success;
}

/* Process a SADB_REGISTER message from the kernel.
 * This will be a response to one of ours, but it may be asynchronous
 * (if kernel modules are loaded and unloaded).
 * Some sanity checking has already been performed.
 */
static void
pfkey_register_response(const struct sadb_msg *msg)
{
	/* Find out what the kernel can support.
	 */
	switch (msg->sadb_msg_satype)
	{
	case SADB_SATYPE_ESP:
#ifndef NO_KERNEL_ALG
		kernel_alg_register_pfkey(msg, sizeof (pfkey_buf));
#endif
		break;
	case SADB_X_SATYPE_IPCOMP:
		/* ??? There ought to be an extension to list the
		 * supported algorithms, but RFC 2367 doesn't
		 * list one for IPcomp.
		 */
		can_do_IPcomp = TRUE;
		break;
	default:
		break;
	}
}

/**  register SA types that can be negotiated */
static void
pfkey_register_proto(unsigned satype, const char *satypename)
{
	struct sadb_ext *extensions[SADB_EXT_MAX + 1];
	pfkey_buf pfb;

	if (!(pfkey_msg_start(SADB_REGISTER, satype, satypename, NULL, extensions)
		  && finish_pfkey_msg(extensions, satypename, "", &pfb)))
	{
		/* ??? should this be loglog */
		plog("no kernel support for %s", satypename);
	}
	else
	{
		pfkey_register_response(&pfb.msg);
		DBG(DBG_KERNEL,
			DBG_log("%s registered with kernel.", satypename));
	}
}

void
pfkey_register(void)
{
	pid = getpid();

	pfkeyfd = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
	if (pfkeyfd == -1)
	{
		exit_log_errno((e, "socket() in init_pfkeyfd()"));
	}

	pfkey_register_proto(SADB_SATYPE_AH, "AH");
	pfkey_register_proto(SADB_SATYPE_ESP, "ESP");
	pfkey_register_proto(SADB_X_SATYPE_IPCOMP, "IPCOMP");

	close(pfkeyfd);
}

/* pfkey interface to the kernel's IPsec mechanism
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003 Herbert Xu.
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

#ifdef KLIPS

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/select.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/queue.h>

#include <freeswan.h>
#include <pfkeyv2.h>
#include <pfkey.h>

#include "constants.h"
#include "defs.h"
#include "kernel.h"
#include "kernel_pfkey.h"
#include "log.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */
#include "demux.h"
#include "nat_traversal.h"
#include "alg_info.h"
#include "kernel_alg.h"


static int pfkeyfd = NULL_FD;

typedef u_int32_t pfkey_seq_t;
static pfkey_seq_t pfkey_seq = 0;       /* sequence number for our PF_KEY messages */

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

#ifdef NEVER /* not needed yet */
static sparse_names pfkey_ext_names = {
		NE(SADB_EXT_RESERVED),
		NE(SADB_EXT_SA),
		NE(SADB_EXT_LIFETIME_CURRENT),
		NE(SADB_EXT_LIFETIME_HARD),
		NE(SADB_EXT_LIFETIME_SOFT),
		NE(SADB_EXT_ADDRESS_SRC),
		NE(SADB_EXT_ADDRESS_DST),
		NE(SADB_EXT_ADDRESS_PROXY),
		NE(SADB_EXT_KEY_AUTH),
		NE(SADB_EXT_KEY_ENCRYPT),
		NE(SADB_EXT_IDENTITY_SRC),
		NE(SADB_EXT_IDENTITY_DST),
		NE(SADB_EXT_SENSITIVITY),
		NE(SADB_EXT_PROPOSAL),
		NE(SADB_EXT_SUPPORTED_AUTH),
		NE(SADB_EXT_SUPPORTED_ENCRYPT),
		NE(SADB_EXT_SPIRANGE),
		NE(SADB_X_EXT_KMPRIVATE),
		NE(SADB_X_EXT_SATYPE2),
		NE(SADB_X_EXT_SA2),
		NE(SADB_X_EXT_ADDRESS_DST2),
		NE(SADB_X_EXT_ADDRESS_SRC_FLOW),
		NE(SADB_X_EXT_ADDRESS_DST_FLOW),
		NE(SADB_X_EXT_ADDRESS_SRC_MASK),
		NE(SADB_X_EXT_ADDRESS_DST_MASK),
		NE(SADB_X_EXT_DEBUG),
		{ 0, sparse_end }
};
#endif /* NEVER */

#undef NE

void
init_pfkey(void)
{
	pid = getpid();

	/* open PF_KEY socket */

	pfkeyfd = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);

	if (pfkeyfd == -1)
		exit_log_errno((e, "socket() in init_pfkeyfd()"));

#ifdef NEVER    /* apparently unsupported! */
	if (fcntl(pfkeyfd, F_SETFL, O_NONBLOCK) != 0)
		exit_log_errno((e, "fcntl(O_NONBLOCK) in init_pfkeyfd()"));
#endif
	if (fcntl(pfkeyfd, F_SETFD, FD_CLOEXEC) != 0)
		exit_log_errno((e, "fcntl(FD_CLOEXEC) in init_pfkeyfd()"));

	DBG(DBG_KLIPS,
		DBG_log("process %u listening for PF_KEY_V2 on file descriptor %d", (unsigned)pid, pfkeyfd));
}

/* Kinds of PF_KEY message from the kernel:
 * - response to a request from us
 *   + ACK/NAK
 *   + Register: indicates transforms supported by kernel
 *   + SPI requested by getspi
 * - Acquire, requesting us to deal with trapped clear packet
 * - expiration of of one of our SAs
 * - messages to other processes
 *
 * To minimize the effect on the event-driven structure of Pluto,
 * responses are dealt with synchronously.  We hope that the Kernel
 * produces them synchronously.  We must "read ahead" in the PF_KEY
 * stream, saving Acquire and Expiry messages that are encountered.
 * We ignore messages to other processes.
 */

typedef union {
		unsigned char bytes[PFKEYv2_MAX_MSGSIZE];
		struct sadb_msg msg;
	} pfkey_buf;

/* queue of unprocessed PF_KEY messages input from kernel
 * Note that the pfkey_buf may be partly allocated, reflecting
 * the variable length nature of the messages.  So the link field
 * must come first.
 */
typedef struct pfkey_item {
		struct pfkey_item *next;
		pfkey_buf buf;
	} pfkey_item;

static pfkey_item *pfkey_iq_head = NULL;        /* oldest */
static pfkey_item *pfkey_iq_tail;       /* youngest */

static bool
pfkey_input_ready(void)
{
	fd_set readfds;
	int ndes;
	struct timeval tm;

	tm.tv_sec = 0;      /* don't wait at all */
	tm.tv_usec = 0;

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

	if (ndes == 0)
		return FALSE;   /* nothing to read */

	passert(ndes == 1 && FD_ISSET(pfkeyfd, &readfds));
	return TRUE;
}

/* get a PF_KEY message from kernel.
 * Returns TRUE is message found, FALSE if no message pending,
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
			return FALSE;

		len = read(pfkeyfd, buf->bytes, sizeof(buf->bytes));

		if (len < 0)
		{
			if (errno == EAGAIN)
				return FALSE;

			log_errno((e, "read() failed in pfkey_get()"));
			return FALSE;
		}
		else if ((size_t) len < sizeof(buf->msg))
		{
			plog("pfkey_get read truncated PF_KEY message: %d bytes; ignoring message"
				, (int) len);
		}
		else if ((size_t) len != buf->msg.sadb_msg_len * IPSEC_PFKEYv2_ALIGN)
		{
			plog("pfkey_get read PF_KEY message with length %d that doesn't equal sadb_msg_len %u * %u; ignoring message"
				, (int) len
				, (unsigned) buf->msg.sadb_msg_len
				, (unsigned) IPSEC_PFKEYv2_ALIGN);
		}
		else if (!(buf->msg.sadb_msg_pid == (unsigned)pid
		|| (buf->msg.sadb_msg_pid == 0 && buf->msg.sadb_msg_type == SADB_ACQUIRE)
		|| (buf->msg.sadb_msg_type == SADB_REGISTER)
		|| (buf->msg.sadb_msg_pid == 0 && buf->msg.sadb_msg_type == SADB_X_NAT_T_NEW_MAPPING)))
		{
			/* not for us: ignore */
			DBG(DBG_KLIPS,
				DBG_log("pfkey_get: ignoring PF_KEY %s message %u for process %u"
					, sparse_val_show(pfkey_type_names, buf->msg.sadb_msg_type)
					, buf->msg.sadb_msg_seq
					, buf->msg.sadb_msg_pid));
		}
		else
		{
			DBG(DBG_KLIPS,
				DBG_log("pfkey_get: %s message %u"
					, sparse_val_show(pfkey_type_names, buf->msg.sadb_msg_type)
					, buf->msg.sadb_msg_seq));
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
		if (buf->msg.sadb_msg_pid == (unsigned)pid
		&& buf->msg.sadb_msg_seq == seq)
		{
			return TRUE;
		}
		else
		{
			/* Not for us: queue it. */
			size_t bl = buf->msg.sadb_msg_len * IPSEC_PFKEYv2_ALIGN;
			pfkey_item *it = malloc(offsetof(pfkey_item, buf) + bl);

			memcpy(&it->buf, buf, bl);

			it->next = NULL;
			if (pfkey_iq_head == NULL)
			{
				pfkey_iq_head = it;
			}
			else
			{
				pfkey_iq_tail->next = it;
			}
			pfkey_iq_tail = it;
		}
	}
	return FALSE;
}

/* Process a SADB_REGISTER message from the kernel.
 * This will be a response to one of ours, but it may be asynchronous
 * (if kernel modules are loaded and unloaded).
 * Some sanity checking has already been performed.
 */
static void
klips_pfkey_register_response(const struct sadb_msg *msg)
{
	/* Find out what the kernel can support.
	 * In fact, the only question at the moment
	 * is whether it can support IPcomp.
	 * So we ignore the rest.
	 * ??? we really should pay attention to what transforms are supported.
	 */
	switch (msg->sadb_msg_satype)
	{
	case SADB_SATYPE_AH:
		break;
	case SADB_SATYPE_ESP:
#ifndef NO_KERNEL_ALG
		kernel_alg_register_pfkey(msg, sizeof (pfkey_buf));
#endif
		break;
	case SADB_X_SATYPE_COMP:
		/* ??? There ought to be an extension to list the
		 * supported algorithms, but RFC 2367 doesn't
		 * list one for IPcomp.  KLIPS uses SADB_X_CALG_DEFLATE.
		 * Since we only implement deflate, we'll assume this.
		 */
		can_do_IPcomp = TRUE;
		break;
	case SADB_X_SATYPE_IPIP:
		break;
	default:
		break;
	}
}

/* Processs a SADB_ACQUIRE message from KLIPS.
 * Try to build an opportunistic connection!
 * See RFC 2367 "PF_KEY Key Management API, Version 2" 3.1.6
 * <base, address(SD), (address(P)), (identity(SD),) (sensitivity,) proposal>
 * - extensions for source and data IP addresses
 * - optional extensions for identity [not useful for us?]
 * - optional extension for sensitivity [not useful for us?]
 * - expension for proposal [not useful for us?]
 *
 * ??? We must use the sequence number in creating an SA.
 * We actually need to create up to 4 SAs each way.  Which one?
 * I guess it depends on the protocol present in the sadb_msg_satype.
 * For now, we'll ignore this requirement.
 *
 * ??? We need some mechanism to make sure that multiple ACQUIRE messages
 * don't cause a whole bunch of redundant negotiations.
 */
static void
process_pfkey_acquire(pfkey_buf *buf, struct sadb_ext *extensions[SADB_EXT_MAX + 1])
{
	struct sadb_address *srcx = (void *) extensions[SADB_EXT_ADDRESS_SRC];
	struct sadb_address *dstx = (void *) extensions[SADB_EXT_ADDRESS_DST];
	int src_proto = srcx->sadb_address_proto;
	int dst_proto = dstx->sadb_address_proto;
	ip_address *src = (ip_address*)&srcx[1];
	ip_address *dst = (ip_address*)&dstx[1];
	ip_subnet ours, his;
	err_t ugh = NULL;

	/* assumption: we're only catching our own outgoing packets
	 * so source is our end and destination is the other end.
	 * Verifying this is not actually convenient.
	 *
	 * This stylized control structure yields a complaint or
	 * desired results.  For compactness, a pointer value is
	 * treated as a boolean.  Logically, the structure is:
	 * keep going as long as things are OK.
	 */
	if (buf->msg.sadb_msg_pid == 0      /* we only wish to hear from kernel */
	&& !(ugh = src_proto == dst_proto? NULL : "src and dst protocols differ")
	&& !(ugh = addrtypeof(src) == addrtypeof(dst)? NULL : "conflicting address types")
	&& !(ugh = addrtosubnet(src, &ours))
	&& !(ugh = addrtosubnet(dst, &his)))
		record_and_initiate_opportunistic(&ours, &his, src_proto, "%acquire");

	if (ugh != NULL)
		plog("SADB_ACQUIRE message from KLIPS malformed: %s", ugh);

}

/* Handle PF_KEY messages from the kernel that are not dealt with
 * synchronously.  In other words, all but responses to PF_KEY messages
 * that we sent.
 */
static void
pfkey_async(pfkey_buf *buf)
{
	struct sadb_ext *extensions[SADB_EXT_MAX + 1];

	if (pfkey_msg_parse(&buf->msg, NULL, extensions, EXT_BITS_OUT))
	{
		plog("pfkey_async:"
			" unparseable PF_KEY message:"
			" %s len=%d, errno=%d, seq=%d, pid=%d; message ignored"
			, sparse_val_show(pfkey_type_names, buf->msg.sadb_msg_type)
			, buf->msg.sadb_msg_len
			, buf->msg.sadb_msg_errno
			, buf->msg.sadb_msg_seq
			, buf->msg.sadb_msg_pid);
	}
	else
	{
		DBG(DBG_CONTROL | DBG_KLIPS, DBG_log("pfkey_async:"
			" %s len=%u, errno=%u, satype=%u, seq=%u, pid=%u"
			, sparse_val_show(pfkey_type_names, buf->msg.sadb_msg_type)
			, buf->msg.sadb_msg_len
			, buf->msg.sadb_msg_errno
			, buf->msg.sadb_msg_satype
			, buf->msg.sadb_msg_seq
			, buf->msg.sadb_msg_pid));

		switch (buf->msg.sadb_msg_type)
		{
		case SADB_REGISTER:
			kernel_ops->pfkey_register_response(&buf->msg);
			break;
		case SADB_ACQUIRE:
			/* to simulate loss of ACQUIRE, delete this call */
			process_pfkey_acquire(buf, extensions);
			break;
		case SADB_X_NAT_T_NEW_MAPPING:
			process_pfkey_nat_t_new_mapping(&(buf->msg), extensions);
			break;
		default:
			/* ignored */
			break;
		}
	}
}

/* asynchronous messages from our queue */
static void
pfkey_dequeue(void)
{
	while (pfkey_iq_head != NULL)
	{
		pfkey_item *it = pfkey_iq_head;

		pfkey_async(&it->buf);
		pfkey_iq_head = it->next;
		free(it);
	}

	/* Handle any orphaned holds, but only if no pfkey input is pending.
	 * For each, we initiate Opportunistic.
	 * note: we don't need to advance the pointer because
	 * record_and_initiate_opportunistic will remove the current
	 * record each time we call it.
	 */
	while (orphaned_holds != NULL && !pfkey_input_ready())
	  record_and_initiate_opportunistic(&orphaned_holds->ours
										, &orphaned_holds->his
										, orphaned_holds->transport_proto
										, "%hold found-pfkey");

}

/* asynchronous messages directly from PF_KEY socket */
static void
pfkey_event(void)
{
	pfkey_buf buf;

	if (pfkey_get(&buf))
		pfkey_async(&buf);
}

static bool
pfkey_build(int error
, const char *description
, const char *text_said
, struct sadb_ext *extensions[SADB_EXT_MAX + 1])
{
	if (error == 0)
	{
		return TRUE;
	}
	else
	{
		loglog(RC_LOG_SERIOUS, "building of %s %s failed, code %d"
			, description, text_said, error);
		pfkey_extensions_free(extensions);
		return FALSE;
	}
}

/* pfkey_extensions_init + pfkey_build + pfkey_msg_hdr_build */
static bool
pfkey_msg_start(u_int8_t msg_type
, u_int8_t satype
, const char *description
, const char *text_said
, struct sadb_ext *extensions[SADB_EXT_MAX + 1])
{
	pfkey_extensions_init(extensions);
	return pfkey_build(pfkey_msg_hdr_build(&extensions[0], msg_type
			, satype, 0, ++pfkey_seq, pid)
		, description, text_said, extensions);
}

/* pfkey_build + pfkey_address_build */
static bool
pfkeyext_address(u_int16_t exttype
, const ip_address *address
, const char *description
, const char *text_said
, struct sadb_ext *extensions[SADB_EXT_MAX + 1])
{
	/* the following variable is only needed to silence
	 * a warning caused by the fact that the argument
	 * to sockaddrof is NOT pointer to const!
	 */
	ip_address t = *address;

	return pfkey_build(pfkey_address_build(extensions + exttype
			, exttype, 0, 0, sockaddrof(&t))
		, description, text_said, extensions);
}

/* pfkey_build + pfkey_x_protocol_build */
static bool
pfkeyext_protocol(int transport_proto
, const char *description
, const char *text_said
, struct sadb_ext *extensions[SADB_EXT_MAX + 1])
{
	return (transport_proto == 0)? TRUE
		: pfkey_build(
			pfkey_x_protocol_build(extensions + SADB_X_EXT_PROTOCOL, transport_proto)
			, description, text_said, extensions);
}


/* Finish (building, sending, accepting response for) PF_KEY message.
 * If response isn't NULL, the response from the kernel will be
 * placed there (and its errno field will not be examined).
 * Returns TRUE iff all appears well.
 */
static bool
finish_pfkey_msg(struct sadb_ext *extensions[SADB_EXT_MAX + 1]
, const char *description
, const char *text_said
, pfkey_buf *response)
{
	struct sadb_msg *pfkey_msg;
	bool success = TRUE;
	int error;

	error = pfkey_msg_build(&pfkey_msg, extensions, EXT_BITS_IN);

	if (error != 0)
	{
		loglog(RC_LOG_SERIOUS, "pfkey_msg_build of %s %s failed, code %d"
			, description, text_said, error);
		success = FALSE;
	}
	else
	{
		size_t len = pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN;

		DBG(DBG_KLIPS,
			DBG_log("finish_pfkey_msg: %s message %u for %s %s"
				, sparse_val_show(pfkey_type_names, pfkey_msg->sadb_msg_type)
				, pfkey_msg->sadb_msg_seq
				, description, text_said);
			DBG_dump(NULL, (void *) pfkey_msg, len));

		if (!no_klips)
		{
			ssize_t r = write(pfkeyfd, pfkey_msg, len);

			if (r != (ssize_t)len)
			{
				if (r < 0)
				{
					log_errno((e
						, "pfkey write() of %s message %u"
						  " for %s %s failed"
						, sparse_val_show(pfkey_type_names
							, pfkey_msg->sadb_msg_type)
						, pfkey_msg->sadb_msg_seq
						, description, text_said));
				}
				else
				{
					loglog(RC_LOG_SERIOUS
						, "ERROR: pfkey write() of %s message %u"
						  " for %s %s truncated: %ld instead of %ld"
						, sparse_val_show(pfkey_type_names
							, pfkey_msg->sadb_msg_type)
						, pfkey_msg->sadb_msg_seq
						, description, text_said
						, (long)r, (long)len);
				}
				success = FALSE;

				/* if we were compiled with debugging, but we haven't already
				 * dumped the KLIPS command, do so.
				 */
#ifdef DEBUG
				if ((cur_debugging & DBG_KLIPS) == 0)
					DBG_dump(NULL, (void *) pfkey_msg, len);
#endif
			}
			else
			{
				/* Check response from KLIPS.
				 * It ought to be an echo, perhaps with additional info.
				 * If the caller wants it, response will point to space.
				 */
				pfkey_buf b;
				pfkey_buf *bp = response != NULL? response : &b;

				if (!pfkey_get_response(bp, ((struct sadb_msg *) extensions[0])->sadb_msg_seq))
				{
					loglog(RC_LOG_SERIOUS
						, "ERROR: no response to our PF_KEY %s message for %s %s"
						, sparse_val_show(pfkey_type_names, pfkey_msg->sadb_msg_type)
						, description, text_said);
					success = FALSE;
				}
				else if (pfkey_msg->sadb_msg_type != bp->msg.sadb_msg_type)
				{
					loglog(RC_LOG_SERIOUS
						, "FreeS/WAN ERROR: response to our PF_KEY %s message for %s %s was of wrong type (%s)"
						, sparse_name(pfkey_type_names, pfkey_msg->sadb_msg_type)
						, description, text_said
						, sparse_val_show(pfkey_type_names, bp->msg.sadb_msg_type));
					success = FALSE;
				}
				else if (response == NULL && bp->msg.sadb_msg_errno != 0)
				{
					/* KLIPS is signalling a problem */
					loglog(RC_LOG_SERIOUS
						, "ERROR: PF_KEY %s response for %s %s included errno %u: %s"
						, sparse_val_show(pfkey_type_names, pfkey_msg->sadb_msg_type)
						, description, text_said
						, (unsigned) bp->msg.sadb_msg_errno
						, strerror(bp->msg.sadb_msg_errno));
					success = FALSE;
				}
			}
		}
	}

	/* all paths must exit this way to free resources */
	pfkey_extensions_free(extensions);
	pfkey_msg_free(&pfkey_msg);
	return success;
}

/*  register SA types that can be negotiated */
void
pfkey_register_proto(unsigned satype, const char *satypename)
{
	struct sadb_ext *extensions[SADB_EXT_MAX + 1];
	pfkey_buf pfb;

	if (!(pfkey_msg_start(SADB_REGISTER
	  , satype
	  , satypename, NULL, extensions)
	&& finish_pfkey_msg(extensions, satypename, "", &pfb)))
	{
		/* ??? should this be loglog */
		plog("no KLIPS support for %s", satypename);
	}
	else
	{
		kernel_ops->pfkey_register_response(&pfb.msg);
		DBG(DBG_KLIPS,
			DBG_log("%s registered with kernel.", satypename));
	}
}

static void
klips_pfkey_register(void)
{
	pfkey_register_proto(SADB_SATYPE_AH, "AH");
	pfkey_register_proto(SADB_SATYPE_ESP, "ESP");
	can_do_IPcomp = FALSE;  /* until we get a response from KLIPS */
	pfkey_register_proto(SADB_X_SATYPE_COMP, "IPCOMP");
	pfkey_register_proto(SADB_X_SATYPE_IPIP, "IPIP");
}

static bool
pfkey_raw_eroute(const ip_address *this_host
				 , const ip_subnet *this_client
				 , const ip_address *that_host
				 , const ip_subnet *that_client
				 , ipsec_spi_t spi
				 , unsigned int satype
				 , unsigned int transport_proto
				 , const struct pfkey_proto_info *proto_info UNUSED
				 , time_t use_lifetime UNUSED
				 , unsigned int op
				 , const char *text_said)
{
	struct sadb_ext *extensions[SADB_EXT_MAX + 1];
	ip_address
		sflow_ska,
		dflow_ska,
		smask_ska,
		dmask_ska;
	int sport = ntohs(portof(&this_client->addr));
	int dport = ntohs(portof(&that_client->addr));

	networkof(this_client, &sflow_ska);
	maskof(this_client, &smask_ska);
	setportof(sport ? ~0:0, &smask_ska);

	networkof(that_client, &dflow_ska);
	maskof(that_client, &dmask_ska);
	setportof(dport ? ~0:0, &dmask_ska);

	if (!pfkey_msg_start(op & ERO_MASK, satype
					   , "pfkey_msg_hdr flow", text_said, extensions))
	{
		return FALSE;
	}

	if (op != ERO_DELETE)
	{
		if (!(pfkey_build(pfkey_sa_build(&extensions[SADB_EXT_SA]
										 , SADB_EXT_SA
										 , spi  /* in network order */
										 , 0, 0, 0, 0, op >> ERO_FLAG_SHIFT)
						  , "pfkey_sa add flow", text_said, extensions)

			&& pfkeyext_address(SADB_EXT_ADDRESS_SRC, this_host
				, "pfkey_addr_s add flow", text_said, extensions)

			&& pfkeyext_address(SADB_EXT_ADDRESS_DST, that_host
								, "pfkey_addr_d add flow", text_said
								, extensions)))
		{
			return FALSE;
		}
	}

	if (!pfkeyext_address(SADB_X_EXT_ADDRESS_SRC_FLOW, &sflow_ska
						  , "pfkey_addr_sflow", text_said, extensions))
	{
		return FALSE;
	}

	if (!pfkeyext_address(SADB_X_EXT_ADDRESS_DST_FLOW, &dflow_ska
						, "pfkey_addr_dflow", text_said, extensions))
	{
		return FALSE;
	}

	if (!pfkeyext_address(SADB_X_EXT_ADDRESS_SRC_MASK, &smask_ska
						, "pfkey_addr_smask", text_said, extensions))
	{
		return FALSE;
	}

	if (!pfkeyext_address(SADB_X_EXT_ADDRESS_DST_MASK, &dmask_ska
						, "pfkey_addr_dmask", text_said, extensions))
	{
		return FALSE;
	}

	if (!pfkeyext_protocol(transport_proto
						, "pfkey_x_protocol", text_said, extensions))
	{
		return FALSE;
	}

	return finish_pfkey_msg(extensions, "flow", text_said, NULL);
}

static bool
pfkey_add_sa(const struct kernel_sa *sa, bool replace)
{
	struct sadb_ext *extensions[SADB_EXT_MAX + 1];

	return pfkey_msg_start(replace ? SADB_UPDATE : SADB_ADD, sa->satype
		, "pfkey_msg_hdr Add SA", sa->text_said, extensions)

	&& pfkey_build(pfkey_sa_build(&extensions[SADB_EXT_SA]
			, SADB_EXT_SA
			, sa->spi   /* in network order */
			, sa->replay_window, SADB_SASTATE_MATURE
			, sa->authalg, sa->encalg ? sa->encalg: sa->compalg, 0)
		, "pfkey_sa Add SA", sa->text_said, extensions)

	&& pfkeyext_address(SADB_EXT_ADDRESS_SRC, sa->src
		, "pfkey_addr_s Add SA", sa->text_said, extensions)

	&& pfkeyext_address(SADB_EXT_ADDRESS_DST, sa->dst
		, "pfkey_addr_d Add SA", sa->text_said, extensions)

	&& (sa->authkeylen == 0
		|| pfkey_build(pfkey_key_build(&extensions[SADB_EXT_KEY_AUTH]
				, SADB_EXT_KEY_AUTH, sa->authkeylen * BITS_PER_BYTE
				, sa->authkey)
			, "pfkey_key_a Add SA", sa->text_said, extensions))

	&& (sa->enckeylen == 0
		|| pfkey_build(pfkey_key_build(&extensions[SADB_EXT_KEY_ENCRYPT]
				, SADB_EXT_KEY_ENCRYPT, sa->enckeylen * BITS_PER_BYTE
				, sa->enckey)
			, "pfkey_key_e Add SA", sa->text_said, extensions))

	&& (sa->natt_type == 0
		|| pfkey_build(pfkey_x_nat_t_type_build(
				&extensions[SADB_X_EXT_NAT_T_TYPE], sa->natt_type),
				"pfkey_nat_t_type Add ESP SA",  sa->text_said, extensions))
	&& (sa->natt_sport == 0
		|| pfkey_build(pfkey_x_nat_t_port_build(
						&extensions[SADB_X_EXT_NAT_T_SPORT], SADB_X_EXT_NAT_T_SPORT,
						sa->natt_sport), "pfkey_nat_t_sport Add ESP SA", sa->text_said,
						extensions))
	&& (sa->natt_dport == 0
		|| pfkey_build(pfkey_x_nat_t_port_build(
						&extensions[SADB_X_EXT_NAT_T_DPORT], SADB_X_EXT_NAT_T_DPORT,
						sa->natt_dport), "pfkey_nat_t_dport Add ESP SA", sa->text_said,
						extensions))
	&& (sa->natt_type == 0 || isanyaddr(sa->natt_oa)
		|| pfkeyext_address(SADB_X_EXT_NAT_T_OA, sa->natt_oa
			, "pfkey_nat_t_oa Add ESP SA", sa->text_said, extensions))

	&& finish_pfkey_msg(extensions, "Add SA", sa->text_said, NULL);

}

static bool
pfkey_grp_sa(const struct kernel_sa *sa0, const struct kernel_sa *sa1)
{
	struct sadb_ext *extensions[SADB_EXT_MAX + 1];

	return pfkey_msg_start(SADB_X_GRPSA, sa1->satype
		, "pfkey_msg_hdr group", sa1->text_said, extensions)

	&& pfkey_build(pfkey_sa_build(&extensions[SADB_EXT_SA]
			, SADB_EXT_SA
			, sa1->spi  /* in network order */
			, 0, 0, 0, 0, 0)
		, "pfkey_sa group", sa1->text_said, extensions)

	&& pfkeyext_address(SADB_EXT_ADDRESS_DST, sa1->dst
		, "pfkey_addr_d group", sa1->text_said, extensions)

	&& pfkey_build(pfkey_x_satype_build(&extensions[SADB_X_EXT_SATYPE2]
			, sa0->satype)
		, "pfkey_satype group", sa0->text_said, extensions)

	&& pfkey_build(pfkey_sa_build(&extensions[SADB_X_EXT_SA2]
			, SADB_X_EXT_SA2
			, sa0->spi  /* in network order */
			, 0, 0, 0, 0, 0)
		, "pfkey_sa2 group", sa0->text_said, extensions)

	&& pfkeyext_address(SADB_X_EXT_ADDRESS_DST2, sa0->dst
		, "pfkey_addr_d2 group", sa0->text_said, extensions)

	&& finish_pfkey_msg(extensions, "group", sa1->text_said, NULL);
}

static bool
pfkey_del_sa(const struct kernel_sa *sa)
{
	struct sadb_ext *extensions[SADB_EXT_MAX + 1];

	return pfkey_msg_start(SADB_DELETE, proto2satype(sa->proto)
		, "pfkey_msg_hdr delete SA", sa->text_said, extensions)

	&& pfkey_build(pfkey_sa_build(&extensions[SADB_EXT_SA]
			, SADB_EXT_SA
			, sa->spi   /* in host order */
			, 0, SADB_SASTATE_MATURE, 0, 0, 0)
		, "pfkey_sa delete SA", sa->text_said, extensions)

	&& pfkeyext_address(SADB_EXT_ADDRESS_SRC, sa->src
		, "pfkey_addr_s delete SA", sa->text_said, extensions)

	&& pfkeyext_address(SADB_EXT_ADDRESS_DST, sa->dst
		, "pfkey_addr_d delete SA", sa->text_said, extensions)

	&& finish_pfkey_msg(extensions, "Delete SA", sa->text_said, NULL);
}

void
pfkey_close(void)
{
	while (pfkey_iq_head != NULL)
	{
		pfkey_item *it = pfkey_iq_head;

		pfkey_iq_head = it->next;
		free(it);
	}

	close(pfkeyfd);
	pfkeyfd = NULL_FD;
}

const struct kernel_ops klips_kernel_ops = {
		type: KERNEL_TYPE_KLIPS,
		async_fdp: &pfkeyfd,

		pfkey_register: klips_pfkey_register,
		pfkey_register_response: klips_pfkey_register_response,
		process_queue: pfkey_dequeue,
		process_msg: pfkey_event,
		raw_eroute: pfkey_raw_eroute,
		add_sa: pfkey_add_sa,
		grp_sa: pfkey_grp_sa,
		del_sa: pfkey_del_sa,
		get_sa: NULL,
		get_spi: NULL,
		inbound_eroute: FALSE,
		policy_lifetime: FALSE,
		init: NULL
};
#endif /* KLIPS */

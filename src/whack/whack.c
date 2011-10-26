/* command interface to Pluto
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <assert.h>

#include <freeswan.h>

#include <utils/optionsfrom.h>

#include "constants.h"
#include "defs.h"
#include "whack.h"

static void help(void)
{
	fprintf(stderr
		, "Usage:\n\n"
		"all forms:"
			" [--optionsfrom <filename>]"
			" [--ctlbase <path>]"
			" [--label <string>]"
			"\n\n"
		"help: whack"
			" [--help]"
			" [--version]"
			"\n\n"
		"connection: whack"
			" --name <connection_name>"
			" \\\n   "
			" [--ipv4 | --ipv6]"
			" [--tunnelipv4 | --tunnelipv6]"
			" \\\n   "
			" (--host <ip-address> | --id <identity>)"
			" \\\n   "
			" [--cert <path>]"
			" [--ca <distinguished name>]"
			" [--sendcert <policy>]"
			" \\\n   "
			" [--groups <access control groups>]"
			" \\\n   "
			" [--ikeport <port-number>]"
			" [--nexthop <ip-address>]"
			" [--srcip <ip-address>]"
			" \\\n   "
			" [--client <subnet> | --clientwithin <address range>]"
			" [--clientprotoport <protocol>/<port>]"
			" \\\n   "
			" [--dnskeyondemand]"
			" [--updown <updown>]"
			" \\\n   "
			" --to"
			" (--host <ip-address> | --id <identity>)"
			" \\\n   "
			" [--cert <path>]"
			" [--ca <distinguished name>]"
			" [--sendcert <policy>]"
			" \\\n   "
			" [--ikeport <port-number>]"
			" [--nexthop <ip-address>]"
			" [--srcip <ip-address>]"
			" \\\n   "
			" [--client <subnet> | --clientwithin <address range>]"
			" [--clientprotoport <protocol>/<port>]"
			" \\\n   "
			" [--dnskeyondemand]"
			" [--updown <updown>]"
			" [--psk]"
			" [--rsasig]"
			" \\\n   "
			" [--encrypt]"
			" [--authenticate]"
			" [--compress]"
			" [--tunnel]"
			" [--pfs]"
			" \\\n   "
			" [--ikelifetime <seconds>]"
			" [--ipseclifetime <seconds>]"
			" \\\n   "
			" [--reykeymargin <seconds>]"
			" [--reykeyfuzz <percentage>]"
			" \\\n   "
			" [--keyingtries <count>]"
			" \\\n   "
			" [--esp <esp-algos>]"
			" \\\n   "
			" [--dontrekey]"

			" [--dpdaction (none|clear|hold|restart)]"
			" \\\n   "
			" [--dpddelay <seconds> --dpdtimeout <seconds>]"
			" \\\n   "
			" [--initiateontraffic|--pass|--drop|--reject]"
			" \\\n   "
			" [--failnone|--failpass|--faildrop|--failreject]"
			"\n\n"
		"routing: whack"
			" (--route | --unroute)"
			" --name <connection_name>"
			"\n\n"
		"initiation:"
			"\n "
			" whack"
			" (--initiate | --terminate)"
			" --name <connection_name>"
			" [--asynchronous]"
			"\n\n"
		"opportunistic initiation: whack"
			" [--tunnelipv4 | --tunnelipv6]"
			" \\\n   "
			" --oppohere <ip-address>"
			" --oppothere <ip-address>"
			"\n\n"
		"delete: whack"
			" --delete"
			" (--name <connection_name> | --caname <ca name>)"
			"\n\n"
		"deletestate: whack"
			" --deletestate <state_object_number>"
			" --crash <ip-address>"
			"\n\n"
		"pubkey: whack"
			" --keyid <id>"
			" [--addkey]"
			" [--pubkeyrsa <key>]"
			"\n\n"
		"myid: whack"
			" --myid <id>"
			"\n\n"
		"ca: whack"
			" --caname <name>"
			" --cacert <path>"
			" \\\n   "
			" [--ldaphost <hostname>]"
			" [--ldapbase <base>]"
			" \\\n   "
			" [--crluri <uri>]"
			" [--crluri2 <uri>]"
			" [--ocspuri <uri>]"
			" [--strictcrlpolicy]"
			"\n\n"
#ifdef DEBUG
		"debug: whack [--name <connection_name>]"
			" \\\n   "
			" [--debug-none]"
			" [--debug-all]"
			" \\\n   "
			" [--debug-raw]"
			" [--debug-crypt]"
			" [--debug-parsing]"
			" [--debug-emitting]"
			" \\\n   "
			" [--debug-control]"
			" [--debug-lifecycle]"
			" [--debug-kernel]"
			" [--debug-dns]"
			" \\\n   "
			" [--debug-natt]"
			" [--debug-oppo]"
			" [--debug-controlmore]"
			" [--debug-private]"
			"\n\n"
#endif
		"leases: whack --leases"
			" [--name <connection_name>]"
			" [--lease-addr <ip-address> | --lease-id <identity>]"
			"\n\n"
		"listen: whack"
			" (--listen | --unlisten)"
			"\n\n"
		"list: whack [--utc]"
			" [--listalgs]"
			" [--listpubkeys]"
			" [--listcerts]"
			" [--listcacerts]"
			" \\\n   "
			" [--listacerts]"
			" [--listaacerts]"
			" [--listocspcerts]"
			" [--listgroups]"
			" \\\n   "
			" [--listcainfos]"
			" [--listcrls]"
			" [--listocsp]"
			" [--listcards]"
			" [--listplugins]"
			" [--listall]"
			"\n\n"
		"purge: whack"
			" [--purgeocsp]"
			"\n\n"
		"reread: whack"
			" [--rereadsecrets]"
			" [--rereadcacerts]"
			" [--rereadaacerts]"
			" \\\n   "
			" [--rereadocspcerts]"
			" [--rereadacerts]"
			" [--rereadcrls]"
			" [--rereadall]"
			"\n\n"
		"status: whack"
			" [--name <connection_name>] --status|--statusall"
			"\n\n"
		"scdecrypt: whack"
			" --scencrypt|scdecrypt <value>"
			" [--inbase <base>]"
			" [--outbase <base>]"
			" [--keyid <id>]"
			"\n\n"
		"shutdown: whack"
			" --shutdown"
			"\n\n"
		"strongSwan "VERSION"\n");
}

static const char *label = NULL;        /* --label operand, saved for diagnostics */

static const char *name = NULL; /* --name operand, saved for diagnostics */

/* options read by optionsfrom */
options_t *options;

/**
 * exit whack after cleaning up
 */
static void whack_exit(int status)
{
	options->destroy(options);
	exit(status);
}

/**
 * print a string as a diagnostic, then exit whack unhappily
 */
static void diag(const char *mess)
{
	if (mess != NULL)
	{
		fprintf(stderr, "whack error: ");
		if (label != NULL)
		{
			fprintf(stderr, "%s ", label);
		}
		if (name != NULL)
		{
			fprintf(stderr, "\"%s\" ", name);
		}
		fprintf(stderr, "%s\n", mess);
	}
	whack_exit(RC_WHACK_PROBLEM);
}

/* conditially calls diag; prints second arg, if non-NULL, as quoted string */
static void diagq(err_t ugh, const char *this)
{
	if (ugh != NULL)
	{
		if (this == NULL)
		{
			diag(ugh);
		}
		else
		{
			char buf[120];      /* arbitrary limit */

			snprintf(buf, sizeof(buf), "%s \"%s\"", ugh, this);
			diag(buf);
		}
	}
}

/* complex combined operands return one of these enumerated values
 * Note: these become flags in an lset_t.  Since there are more than
 * 32, we partition them into:
 * - OPT_* options (most random options)
 * - LST_* options (list various internal data)
 * - DBGOPT_* option (DEBUG options)
 * - END_* options (End description options)
 * - CD_* options (Connection Description options)
 * - CA_* options (CA description options)
 */
enum {
#   define OPT_FIRST    OPT_CTLBASE
	OPT_CTLBASE,
	OPT_NAME,

	OPT_CD,

	OPT_KEYID,
	OPT_ADDKEY,
	OPT_PUBKEYRSA,

	OPT_MYID,

	OPT_ROUTE,
	OPT_UNROUTE,

	OPT_INITIATE,
	OPT_TERMINATE,
	OPT_DELETE,
	OPT_DELETESTATE,
	OPT_LISTEN,
	OPT_UNLISTEN,

	OPT_LEASES,
	OPT_LEASEADDR,
	OPT_LEASEID,

	OPT_PURGEOCSP,

	OPT_REREADSECRETS,
	OPT_REREADCACERTS,
	OPT_REREADAACERTS,
	OPT_REREADOCSPCERTS,
	OPT_REREADACERTS,
	OPT_REREADCRLS,
	OPT_REREADALL,

	OPT_STATUS,
	OPT_STATUSALL,
	OPT_SHUTDOWN,

	OPT_OPPO_HERE,
	OPT_OPPO_THERE,

	OPT_ASYNC,
	OPT_DELETECRASH,

#   define OPT_LAST OPT_ASYNC   /* last "normal" option */

/* Smartcard options */

#   define SC_FIRST SC_ENCRYPT  /* first smartcard option */

	SC_ENCRYPT,
	SC_DECRYPT,
	SC_INBASE,
	SC_OUTBASE,

#   define SC_LAST SC_OUTBASE   /* last "smartcard" option */

/* List options */

#   define LST_FIRST LST_UTC    /* first list option */
	LST_UTC,
	LST_ALGS,
	LST_PUBKEYS,
	LST_CERTS,
	LST_CACERTS,
	LST_ACERTS,
	LST_AACERTS,
	LST_OCSPCERTS,
	LST_GROUPS,
	LST_CAINFOS,
	LST_CRLS,
	LST_OCSP,
	LST_CARDS,
	LST_PLUGINS,
	LST_ALL,

#   define LST_LAST LST_ALL     /* last list option */

/* Connection End Description options */

#   define END_FIRST END_HOST   /* first end description */
	END_HOST,
	END_ID,
	END_CERT,
	END_CA,
	END_SENDCERT,
	END_GROUPS,
	END_IKEPORT,
	END_NEXTHOP,
	END_CLIENT,
	END_CLIENTWITHIN,
	END_CLIENTPROTOPORT,
	END_DNSKEYONDEMAND,
	END_SRCIP,
	END_HOSTACCESS,
	END_UPDOWN,

#define END_LAST  END_UPDOWN    /* last end description*/

/* Connection Description options -- segregated */

#   define CD_FIRST CD_TO       /* first connection description */
	CD_TO,

#   define CD_POLICY_FIRST  CD_PSK
	CD_PSK,     /* same order as POLICY_* */
	CD_RSASIG,  /* same order as POLICY_* */
	CD_ENCRYPT, /* same order as POLICY_* */
	CD_AUTHENTICATE,    /* same order as POLICY_* */
	CD_COMPRESS,        /* same order as POLICY_* */
	CD_TUNNEL,  /* same order as POLICY_* */
	CD_PFS,     /* same order as POLICY_* */
	CD_DISABLEARRIVALCHECK,     /* same order as POLICY_* */
	CD_SHUNT0,  /* same order as POLICY_* */
	CD_SHUNT1,  /* same order as POLICY_* */
	CD_FAIL0,   /* same order as POLICY_* */
	CD_FAIL1,   /* same order as POLICY_* */
	CD_DONT_REKEY,      /* same order as POLICY_* */

	CD_TUNNELIPV4,
	CD_TUNNELIPV6,
	CD_CONNIPV4,
	CD_CONNIPV6,

	CD_IKELIFETIME,
	CD_IPSECLIFETIME,
	CD_RKMARGIN,
	CD_RKFUZZ,
	CD_KTRIES,
	CD_DPDACTION,
	CD_DPDDELAY,
	CD_DPDTIMEOUT,
	CD_IKE,
	CD_PFSGROUP,
	CD_ESP,

#   define CD_LAST CD_ESP       /* last connection description */

/* Certificate Authority (CA) description options */

#   define CA_FIRST CA_NAME     /* first ca description */

	CA_NAME,
	CA_CERT,
	CA_LDAPHOST,
	CA_LDAPBASE,
	CA_CRLURI,
	CA_CRLURI2,
	CA_OCSPURI,
	CA_STRICT

#   define CA_LAST CA_STRICT    /* last ca description */

#ifdef DEBUG    /* must be last so others are less than 32 to fit in lset_t */
#   define DBGOPT_FIRST DBGOPT_NONE
	,
	/* NOTE: these definitions must match DBG_* and IMPAIR_* in constants.h */
	DBGOPT_NONE,
	DBGOPT_ALL,

	DBGOPT_RAW,         /* same order as DBG_* */
	DBGOPT_CRYPT,       /* same order as DBG_* */
	DBGOPT_PARSING,     /* same order as DBG_* */
	DBGOPT_EMITTING,    /* same order as DBG_* */
	DBGOPT_CONTROL,     /* same order as DBG_* */
	DBGOPT_LIFECYCLE,   /* same order as DBG_* */
	DBGOPT_KERNEL,      /* same order as DBG_* */
	DBGOPT_DNS,         /* same order as DBG_* */
	DBGOPT_NATT,        /* same order as DBG_* */
	DBGOPT_OPPO,        /* same order as DBG_* */
	DBGOPT_CONTROLMORE, /* same order as DBG_* */

	DBGOPT_PRIVATE,     /* same order as DBG_* */

	DBGOPT_IMPAIR_DELAY_ADNS_KEY_ANSWER,        /* same order as IMPAIR_* */
	DBGOPT_IMPAIR_DELAY_ADNS_TXT_ANSWER,        /* same order as IMPAIR_* */
	DBGOPT_IMPAIR_BUST_MI2,     /* same order as IMPAIR_* */
	DBGOPT_IMPAIR_BUST_MR2      /* same order as IMPAIR_* */

#   define DBGOPT_LAST DBGOPT_IMPAIR_BUST_MR2
#endif

};

/* Carve up space for result from getop_long.
 * Stupidly, the only result is an int.
 * Numeric arg is bit immediately left of basic value.
 *
 */
#define OPTION_OFFSET   256     /* to get out of the way of letter options */
#define NUMERIC_ARG (1 << 9)    /* expect a numeric argument */
#define AUX_SHIFT   10  /* amount to shift for aux information */

static const struct option long_opts[] = {
#   define OO   OPTION_OFFSET
	/* name, has_arg, flag, val */

	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'v' },
	{ "optionsfrom", required_argument, NULL, '+' },
	{ "label", required_argument, NULL, 'l' },

	{ "ctlbase", required_argument, NULL, OPT_CTLBASE + OO },
	{ "name", required_argument, NULL, OPT_NAME + OO },

	{ "keyid", required_argument, NULL, OPT_KEYID + OO },
	{ "addkey", no_argument, NULL, OPT_ADDKEY + OO },
	{ "pubkeyrsa", required_argument, NULL, OPT_PUBKEYRSA + OO },

	{ "myid", required_argument, NULL, OPT_MYID + OO },

	{ "route", no_argument, NULL, OPT_ROUTE + OO },
	{ "unroute", no_argument, NULL, OPT_UNROUTE + OO },

	{ "initiate", no_argument, NULL, OPT_INITIATE + OO },
	{ "terminate", no_argument, NULL, OPT_TERMINATE + OO },
	{ "delete", no_argument, NULL, OPT_DELETE + OO },
	{ "deletestate", required_argument, NULL, OPT_DELETESTATE + OO + NUMERIC_ARG },
	{ "crash", required_argument, NULL, OPT_DELETECRASH + OO },
	{ "listen", no_argument, NULL, OPT_LISTEN + OO },
	{ "unlisten", no_argument, NULL, OPT_UNLISTEN + OO },

	{ "leases", no_argument, NULL, OPT_LEASES + OO },
	{ "lease-addr", required_argument, NULL, OPT_LEASEADDR + OO },
	{ "lease-id", required_argument, NULL, OPT_LEASEID + OO },

	{ "purgeocsp", no_argument, NULL, OPT_PURGEOCSP + OO },

	{ "rereadsecrets", no_argument, NULL, OPT_REREADSECRETS + OO },
	{ "rereadcacerts", no_argument, NULL, OPT_REREADCACERTS + OO },
	{ "rereadaacerts", no_argument, NULL, OPT_REREADAACERTS + OO },
	{ "rereadocspcerts", no_argument, NULL, OPT_REREADOCSPCERTS + OO },
	{ "rereadacerts", no_argument, NULL, OPT_REREADACERTS + OO },
	{ "rereadcrls", no_argument, NULL, OPT_REREADCRLS + OO },
	{ "rereadall", no_argument, NULL, OPT_REREADALL + OO },
	{ "status", no_argument, NULL, OPT_STATUS + OO },
	{ "statusall", no_argument, NULL, OPT_STATUSALL + OO },
	{ "shutdown", no_argument, NULL, OPT_SHUTDOWN + OO },

	{ "oppohere", required_argument, NULL, OPT_OPPO_HERE + OO },
	{ "oppothere", required_argument, NULL, OPT_OPPO_THERE + OO },

	{ "asynchronous", no_argument, NULL, OPT_ASYNC + OO },

	/* smartcard options */

	{ "scencrypt", required_argument, NULL, SC_ENCRYPT + OO },
	{ "scdecrypt", required_argument, NULL, SC_DECRYPT + OO },
	{ "inbase", required_argument, NULL, SC_INBASE + OO },
	{ "outbase", required_argument, NULL, SC_OUTBASE + OO },

	/* list options */

	{ "utc", no_argument, NULL, LST_UTC + OO },
	{ "listalgs", no_argument, NULL, LST_ALGS + OO },
	{ "listpubkeys", no_argument, NULL, LST_PUBKEYS + OO },
	{ "listcerts", no_argument, NULL, LST_CERTS + OO },
	{ "listcacerts", no_argument, NULL, LST_CACERTS + OO },
	{ "listacerts", no_argument, NULL, LST_ACERTS + OO },
	{ "listaacerts", no_argument, NULL, LST_AACERTS + OO },
	{ "listocspcerts", no_argument, NULL, LST_OCSPCERTS + OO },
	{ "listgroups", no_argument, NULL, LST_GROUPS + OO },
	{ "listcainfos", no_argument, NULL, LST_CAINFOS + OO },
	{ "listcrls", no_argument, NULL, LST_CRLS + OO },
	{ "listocsp", no_argument, NULL, LST_OCSP + OO },
	{ "listcards", no_argument, NULL, LST_CARDS + OO },
	{ "listplugins", no_argument, NULL, LST_PLUGINS + OO },
	{ "listall", no_argument, NULL, LST_ALL + OO },

	/* options for an end description */

	{ "host", required_argument, NULL, END_HOST + OO },
	{ "id", required_argument, NULL, END_ID + OO },
	{ "cert", required_argument, NULL, END_CERT + OO },
	{ "ca", required_argument, NULL, END_CA + OO },
	{ "sendcert", required_argument, NULL, END_SENDCERT + OO },
	{ "groups", required_argument, NULL, END_GROUPS + OO },
	{ "ikeport", required_argument, NULL, END_IKEPORT + OO + NUMERIC_ARG },
	{ "nexthop", required_argument, NULL, END_NEXTHOP + OO },
	{ "client", required_argument, NULL, END_CLIENT + OO },
	{ "clientwithin", required_argument, NULL, END_CLIENTWITHIN + OO },
	{ "clientprotoport", required_argument, NULL, END_CLIENTPROTOPORT + OO },
	{ "dnskeyondemand", no_argument, NULL, END_DNSKEYONDEMAND + OO },
	{ "srcip",  required_argument, NULL, END_SRCIP + OO },
	{ "hostaccess", no_argument, NULL, END_HOSTACCESS + OO },
	{ "updown", required_argument, NULL, END_UPDOWN + OO },

	/* options for a connection description */

	{ "to", no_argument, NULL, CD_TO + OO },

	{ "psk", no_argument, NULL, CD_PSK + OO },
	{ "rsasig", no_argument, NULL, CD_RSASIG + OO },

	{ "encrypt", no_argument, NULL, CD_ENCRYPT + OO },
	{ "authenticate", no_argument, NULL, CD_AUTHENTICATE + OO },
	{ "compress", no_argument, NULL, CD_COMPRESS + OO },
	{ "tunnel", no_argument, NULL, CD_TUNNEL + OO },
	{ "tunnelipv4", no_argument, NULL, CD_TUNNELIPV4 + OO },
	{ "tunnelipv6", no_argument, NULL, CD_TUNNELIPV6 + OO },
	{ "pfs", no_argument, NULL, CD_PFS + OO },
	{ "disablearrivalcheck", no_argument, NULL, CD_DISABLEARRIVALCHECK + OO },
	{ "initiateontraffic", no_argument, NULL
		, CD_SHUNT0 + (POLICY_SHUNT_TRAP >> POLICY_SHUNT_SHIFT << AUX_SHIFT) + OO },
	{ "pass", no_argument, NULL
		, CD_SHUNT0 + (POLICY_SHUNT_PASS >> POLICY_SHUNT_SHIFT << AUX_SHIFT) + OO },
	{ "drop", no_argument, NULL
		, CD_SHUNT0 + (POLICY_SHUNT_DROP >> POLICY_SHUNT_SHIFT << AUX_SHIFT) + OO },
	{ "reject", no_argument, NULL
		, CD_SHUNT0 + (POLICY_SHUNT_REJECT >> POLICY_SHUNT_SHIFT << AUX_SHIFT) + OO },
	{ "failnone", no_argument, NULL
		, CD_FAIL0 + (POLICY_FAIL_NONE >> POLICY_FAIL_SHIFT << AUX_SHIFT) + OO },
	{ "failpass", no_argument, NULL
		, CD_FAIL0 + (POLICY_FAIL_PASS >> POLICY_FAIL_SHIFT << AUX_SHIFT) + OO },
	{ "faildrop", no_argument, NULL
		, CD_FAIL0 + (POLICY_FAIL_DROP >> POLICY_FAIL_SHIFT << AUX_SHIFT) + OO },
	{ "failreject", no_argument, NULL
		, CD_FAIL0 + (POLICY_FAIL_REJECT >> POLICY_FAIL_SHIFT << AUX_SHIFT) + OO },
	{ "dontrekey", no_argument, NULL, CD_DONT_REKEY + OO },
	{ "ipv4", no_argument, NULL, CD_CONNIPV4 + OO },
	{ "ipv6", no_argument, NULL, CD_CONNIPV6 + OO },

	{ "ikelifetime", required_argument, NULL, CD_IKELIFETIME + OO + NUMERIC_ARG },
	{ "ipseclifetime", required_argument, NULL, CD_IPSECLIFETIME + OO + NUMERIC_ARG },
	{ "rekeymargin", required_argument, NULL, CD_RKMARGIN + OO + NUMERIC_ARG },
	{ "rekeywindow", required_argument, NULL, CD_RKMARGIN + OO + NUMERIC_ARG }, /* OBSOLETE */
	{ "rekeyfuzz", required_argument, NULL, CD_RKFUZZ + OO + NUMERIC_ARG },
	{ "keyingtries", required_argument, NULL, CD_KTRIES + OO + NUMERIC_ARG },
	{ "dpdaction", required_argument, NULL, CD_DPDACTION + OO },
	{ "dpddelay", required_argument, NULL, CD_DPDDELAY + OO + NUMERIC_ARG },
	{ "dpdtimeout", required_argument, NULL, CD_DPDTIMEOUT + OO + NUMERIC_ARG },
	{ "ike", required_argument, NULL, CD_IKE + OO },
	{ "pfsgroup", required_argument, NULL, CD_PFSGROUP + OO },
	{ "esp", required_argument, NULL, CD_ESP + OO },

	/* options for a ca description */

	{ "caname", required_argument, NULL, CA_NAME + OO },
	{ "cacert", required_argument, NULL, CA_CERT + OO },
	{ "ldaphost", required_argument, NULL, CA_LDAPHOST + OO },
	{ "ldapbase", required_argument, NULL, CA_LDAPBASE + OO },
	{ "crluri", required_argument, NULL, CA_CRLURI + OO },
	{ "crluri2", required_argument, NULL, CA_CRLURI2 + OO },
	{ "ocspuri", required_argument, NULL, CA_OCSPURI + OO },
	{ "strictcrlpolicy", no_argument, NULL, CA_STRICT + OO },

#ifdef DEBUG
	{ "debug-none", no_argument, NULL, DBGOPT_NONE + OO },
	{ "debug-all]", no_argument, NULL, DBGOPT_ALL + OO },
	{ "debug-raw", no_argument, NULL, DBGOPT_RAW + OO },
	{ "debug-crypt", no_argument, NULL, DBGOPT_CRYPT + OO },
	{ "debug-parsing", no_argument, NULL, DBGOPT_PARSING + OO },
	{ "debug-emitting", no_argument, NULL, DBGOPT_EMITTING + OO },
	{ "debug-control", no_argument, NULL, DBGOPT_CONTROL + OO },
	{ "debug-lifecycle", no_argument, NULL, DBGOPT_LIFECYCLE + OO },
	{ "debug-klips", no_argument, NULL, DBGOPT_KERNEL + OO },
	{ "debug-kernel", no_argument, NULL, DBGOPT_KERNEL + OO },
	{ "debug-dns", no_argument, NULL, DBGOPT_DNS + OO },
	{ "debug-natt", no_argument, NULL, DBGOPT_NATT + OO },
	{ "debug-oppo", no_argument, NULL, DBGOPT_OPPO + OO },
	{ "debug-controlmore", no_argument, NULL, DBGOPT_CONTROLMORE + OO },
	{ "debug-private", no_argument, NULL, DBGOPT_PRIVATE + OO },

	{ "impair-delay-adns-key-answer", no_argument, NULL, DBGOPT_IMPAIR_DELAY_ADNS_KEY_ANSWER + OO },
	{ "impair-delay-adns-txt-answer", no_argument, NULL, DBGOPT_IMPAIR_DELAY_ADNS_TXT_ANSWER + OO },
	{ "impair-bust-mi2", no_argument, NULL, DBGOPT_IMPAIR_BUST_MI2 + OO },
	{ "impair-bust-mr2", no_argument, NULL, DBGOPT_IMPAIR_BUST_MR2 + OO },
#endif
#   undef OO
	{ 0,0,0,0 }
};

struct sockaddr_un ctl_addr = { AF_UNIX, DEFAULT_CTLBASE CTL_SUFFIX };

/* helper variables and function to encode strings from whack message */

static char	*next_str,*str_roof;

static bool pack_str(char **p)
{
	const char *s = *p == NULL? "" : *p;        /* note: NULL becomes ""! */
	size_t len = strlen(s) + 1;

	if (str_roof - next_str < (ptrdiff_t)len)
	{
		return FALSE;   /* fishy: no end found */
	}
	else
	{
		strcpy(next_str, s);
		next_str += len;
		*p = NULL;      /* don't send pointers on the wire! */
		return TRUE;
	}
}

static void check_life_time(time_t life, time_t limit, const char *which,
							const whack_message_t *msg)
{
	time_t mint = msg->sa_rekey_margin * (100 + msg->sa_rekey_fuzz) / 100;

	if (life > limit)
	{
		char buf[200];  /* arbitrary limit */

		snprintf(buf, sizeof(buf)
			, "%s [%lu seconds] must be less than %lu seconds"
			, which, (unsigned long)life, (unsigned long)limit);
		diag(buf);
	}
	if ((msg->policy & POLICY_DONT_REKEY) == LEMPTY && life <= mint)
	{
		char buf[200];  /* arbitrary limit */

		snprintf(buf, sizeof(buf)
			, "%s [%lu] must be greater than"
			" rekeymargin*(100+rekeyfuzz)/100 [%lu*(100+%lu)/100 = %lu]"
			, which
			, (unsigned long)life
			, (unsigned long)msg->sa_rekey_margin
			, (unsigned long)msg->sa_rekey_fuzz
			, (unsigned long)mint);
		diag(buf);
	}
}

static void clear_end(whack_end_t *e)
{
	zero(e);
	e->id = NULL;
	e->cert = NULL;
	e->ca = NULL;
	e->updown = NULL;
	e->host_port = IKE_UDP_PORT;
}

static void update_ports(whack_message_t *m)
{
	int port;

	if (m->left.port != 0) {
		port = htons(m->left.port);
		setportof(port, &m->left.host_addr);
		setportof(port, &m->left.client.addr);
	}
	if (m->right.port != 0) {
		port = htons(m->right.port);
		setportof(port, &m->right.host_addr);
		setportof(port, &m->right.client.addr);
	}
}

static void check_end(whack_end_t *this, whack_end_t *that,
					  bool default_nexthop, sa_family_t caf, sa_family_t taf)
{
	if (caf != addrtypeof(&this->host_addr))
		diag("address family of host inconsistent");

	if (default_nexthop)
	{
		if (isanyaddr(&that->host_addr))
			diag("our nexthop must be specified when other host is a %any or %opportunistic");
		this->host_nexthop = that->host_addr;
	}

	if (caf != addrtypeof(&this->host_nexthop))
		diag("address family of nexthop inconsistent");

	if (this->has_client)
	{
		if (taf != subnettypeof(&this->client))
			diag("address family of client subnet inconsistent");
	}
	else
	{
		/* fill in anyaddr-anyaddr as (missing) client subnet */
		ip_address cn;

		diagq(anyaddr(caf, &cn), NULL);
		diagq(rangetosubnet(&cn, &cn, &this->client), NULL);
	}

	/* fill in anyaddr if source IP is not defined */
	if (!this->has_srcip)
		diagq(anyaddr(caf, &this->host_srcip), optarg);

   /* check protocol */
	if (this->protocol != that->protocol)
		diag("the protocol for leftprotoport and rightprotoport must be the same");
}

static void get_secret(int sock)
{
	const char *buf = NULL, *secret;
	int len;

	fflush(stdout);
	usleep(20000); /* give fflush time for flushing */
#ifdef HAVE_GETPASS
	buf = getpass("Enter: ");
#endif
	secret = (buf == NULL)? "" : buf;

	/* send the secret to pluto */
	len = strlen(secret) + 1;
	if (write(sock, secret, len) != len)
	{
		int e = errno;

		fprintf(stderr, "whack: write() failed (%d %s)\n", e, strerror(e));
		exit(RC_WHACK_PROBLEM);
	}
}

/* This is a hack for initiating ISAKMP exchanges. */

int main(int argc, char **argv)
{
	whack_message_t msg;
	char esp_buf[256];  /* uses snprintf */
	lset_t
		opts_seen = LEMPTY,
		sc_seen = LEMPTY,
		lst_seen = LEMPTY,
		cd_seen = LEMPTY,
		ca_seen = LEMPTY,
		end_seen = LEMPTY,
		end_seen_before_to = LEMPTY;
	const char
		*af_used_by = NULL,
		*tunnel_af_used_by = NULL;

	/* check division of numbering space */
#ifdef DEBUG
	assert(OPTION_OFFSET + DBGOPT_LAST < NUMERIC_ARG);
#else
	assert(OPTION_OFFSET + CA_LAST < NUMERIC_ARG);
#endif
	assert(OPT_LAST - OPT_FIRST < (sizeof opts_seen * BITS_PER_BYTE));
	assert(SC_LAST  - SC_FIRST  < (sizeof sc_seen   * BITS_PER_BYTE));
	assert(LST_LAST - LST_FIRST < (sizeof lst_seen  * BITS_PER_BYTE));
	assert(END_LAST - END_FIRST < (sizeof end_seen  * BITS_PER_BYTE));
	assert(CD_LAST  - CD_FIRST  < (sizeof cd_seen   * BITS_PER_BYTE));
	assert(CA_LAST  - CA_FIRST  < (sizeof ca_seen   * BITS_PER_BYTE));
#ifdef DEBUG    /* must be last so others are less than (sizeof cd_seen * BITS_PER_BYTE) to fit in lset_t */
	assert(DBGOPT_LAST - DBGOPT_FIRST < (sizeof cd_seen * BITS_PER_BYTE));
#endif
	/* check that POLICY bit assignment matches with CD_ */
	assert(LELEM(CD_DONT_REKEY - CD_POLICY_FIRST) == POLICY_DONT_REKEY);

	zero(&msg);

	clear_end(&msg.right);      /* left set from this after --to */

	msg.name = NULL;
	msg.keyid = NULL;
	msg.keyval.ptr = NULL;
	msg.esp = NULL;
	msg.ike = NULL;
	msg.pfsgroup = NULL;

   /* if a connection is added via whack then we assume IKEv1 */
	msg.ikev1 = TRUE;

	msg.sa_ike_life_seconds = OAKLEY_ISAKMP_SA_LIFETIME_DEFAULT;
	msg.sa_ipsec_life_seconds = PLUTO_SA_LIFE_DURATION_DEFAULT;
	msg.sa_rekey_margin = SA_REPLACEMENT_MARGIN_DEFAULT;
	msg.sa_rekey_fuzz = SA_REPLACEMENT_FUZZ_DEFAULT;
	msg.sa_keying_tries = SA_REPLACEMENT_RETRIES_DEFAULT;

	msg.addr_family = AF_INET;
	msg.tunnel_addr_family = AF_INET;

	msg.cacert = NULL;
	msg.ldaphost = NULL;
	msg.ldapbase = NULL;
	msg.crluri = NULL;
	msg.crluri2 = NULL;
	msg.ocspuri = NULL;

	options = options_create();

	for (;;)
	{
		int long_index;
		unsigned long opt_whole = 0;  /* numeric argument for some flags */

		/* Note: we don't like the way short options get parsed
		 * by getopt_long, so we simply pass an empty string as
		 * the list.  It could be "hp:d:c:o:eatfs" "NARXPECK".
		 */
		int c = getopt_long(argc, argv, "", long_opts, &long_index) - OPTION_OFFSET;
		int aux = 0;

		/* decode a numeric argument, if expected */
		if (0 <= c)
		{
			if (c & NUMERIC_ARG)
			{
				char *endptr;

				c -= NUMERIC_ARG;
				opt_whole = strtoul(optarg, &endptr, 0);

				if (*endptr != '\0' || endptr == optarg)
					diagq("badly formed numeric argument", optarg);
			}
			if (c >= (1 << AUX_SHIFT))
			{
				aux = c >> AUX_SHIFT;
				c -= aux << AUX_SHIFT;
			}
		}

		/* per-class option processing */
		if (0 <= c && c <= OPT_LAST)
		{
			/* OPT_* options get added to opts_seen.
			 * Reject repeated options (unless later code intervenes).
			 */
			lset_t f = LELEM(c);

			if (opts_seen & f)
				diagq("duplicated flag", long_opts[long_index].name);
			opts_seen |= f;
		}
		else if (SC_FIRST <= c && c <= SC_LAST)
		{
			/* SC_* options get added to sc_seen.
			 * Reject repeated options (unless later code intervenes).
			 */
			lset_t f = LELEM(c - SC_FIRST);

			if (sc_seen & f)
				diagq("duplicated flag", long_opts[long_index].name);
			sc_seen |= f;
		}
		else if (LST_FIRST <= c && c <= LST_LAST)
		{
			/* LST_* options get added to lst_seen.
			 * Reject repeated options (unless later code intervenes).
			 */
			lset_t f = LELEM(c - LST_FIRST);

			if (lst_seen & f)
				diagq("duplicated flag", long_opts[long_index].name);
			lst_seen |= f;
		}
#ifdef DEBUG
		else if (DBGOPT_FIRST <= c && c <= DBGOPT_LAST)
		{
			msg.whack_options = TRUE;
		}
#endif
		else if (END_FIRST <= c && c <= END_LAST)
		{
			/* END_* options are added to end_seen.
			 * Reject repeated options (unless later code intervenes).
			 */
			lset_t f = LELEM(c - END_FIRST);

			if (end_seen & f)
				diagq("duplicated flag", long_opts[long_index].name);
			end_seen |= f;
			opts_seen |= LELEM(OPT_CD);
		}
		else if (CD_FIRST <= c && c <= CD_LAST)
		{
			/* CD_* options are added to cd_seen.
			 * Reject repeated options (unless later code intervenes).
			 */
			lset_t f = LELEM(c - CD_FIRST);

			if (cd_seen & f)
				diagq("duplicated flag", long_opts[long_index].name);
			cd_seen |= f;
			opts_seen |= LELEM(OPT_CD);
		}
		else if (CA_FIRST <= c && c <= CA_LAST)
		{
			/* CA_* options are added to ca_seen.
			 * Reject repeated options (unless later code intervenes).
			 */
			lset_t f = LELEM(c - CA_FIRST);

			if (ca_seen & f)
				diagq("duplicated flag", long_opts[long_index].name);
			ca_seen |= f;
		}

		/* Note: "break"ing from switch terminates loop.
		 * most cases should end with "continue".
		 */
		switch (c)
		{
		case EOF - OPTION_OFFSET:       /* end of flags */
			break;

		case 0 - OPTION_OFFSET: /* long option already handled */
			continue;

		case ':' - OPTION_OFFSET:       /* diagnostic already printed by getopt_long */
		case '?' - OPTION_OFFSET:       /* diagnostic already printed by getopt_long */
			diag(NULL); /* print no additional diagnostic, but exit sadly */
			break;      /* not actually reached */

		case 'h' - OPTION_OFFSET:       /* --help */
			help();
			whack_exit(0);              /* GNU coding standards say to stop here */

		case 'v' - OPTION_OFFSET:       /* --version */
			{
				const char **sp = ipsec_copyright_notice();

				printf("strongSwan "VERSION"\n");
				for (; *sp != NULL; sp++)
					puts(*sp);
			}
			whack_exit(0);   /* GNU coding standards say to stop here */

		case 'l' - OPTION_OFFSET:       /* --label <string> */
			label = optarg;             /* remember for diagnostics */
			continue;

		case '+' - OPTION_OFFSET:       /* --optionsfrom <filename> */
			if (!options->from(options, optarg, &argc, &argv, optind))
			{
				fprintf(stderr, "optionsfrom failed");
				whack_exit(RC_WHACK_PROBLEM);
			}
			continue;

		/* the rest of the options combine in complex ways */

		case OPT_CTLBASE:       /* --port <ctlbase> */
			if (snprintf(ctl_addr.sun_path, sizeof(ctl_addr.sun_path)
			, "%s%s", optarg, CTL_SUFFIX) == -1)
				diag("<ctlbase>" CTL_SUFFIX " must be fit in a sun_addr");
			continue;

		case OPT_NAME:  /* --name <connection-name> */
			name = optarg;
			msg.name = optarg;
			continue;

		case OPT_KEYID: /* --keyid <identity> */
			msg.whack_key = !msg.whack_sc_op;
			msg.keyid = optarg; /* decoded by Pluto */
			continue;

		case OPT_MYID:  /* --myid <identity> */
			msg.whack_myid = TRUE;
			msg.myid = optarg;  /* decoded by Pluto */
			continue;

		case OPT_ADDKEY:        /* --addkey */
			msg.whack_addkey = TRUE;
			continue;

		case OPT_PUBKEYRSA:     /* --pubkeyrsa <key> */
			{
				static char keyspace[RSA_MAX_ENCODING_BYTES];   /* room for 8K bit key */
				char diag_space[TTODATAV_BUF];
				const char *ugh = ttodatav(optarg, 0, 0
					, keyspace, sizeof(keyspace)
					, &msg.keyval.len, diag_space, sizeof(diag_space)
					, TTODATAV_SPACECOUNTS);

				if (ugh != NULL)
				{
					char ugh_space[80]; /* perhaps enough space */

					snprintf(ugh_space, sizeof(ugh_space)
						, "RSA public-key data malformed (%s)", ugh);
					diagq(ugh_space, optarg);
				}
				msg.pubkey_alg = PUBKEY_ALG_RSA;
				msg.keyval.ptr = keyspace;
			}
			continue;

		case OPT_ROUTE: /* --route */
			msg.whack_route = TRUE;
			continue;

		case OPT_UNROUTE:       /* --unroute */
			msg.whack_unroute = TRUE;
			continue;

		case OPT_INITIATE:      /* --initiate */
			msg.whack_initiate = TRUE;
			continue;

		case OPT_TERMINATE:     /* --terminate */
			msg.whack_terminate = TRUE;
			continue;

		case OPT_DELETE:        /* --delete */
			msg.whack_delete = TRUE;
			continue;

		case OPT_DELETESTATE:   /* --deletestate <state_object_number> */
			msg.whack_deletestate = TRUE;
			msg.whack_deletestateno = opt_whole;
			continue;

		case OPT_DELETECRASH:   /* --crash <ip-address> */
			msg.whack_crash = TRUE;
			tunnel_af_used_by = long_opts[long_index].name;
			diagq(ttoaddr(optarg, 0, msg.tunnel_addr_family, &msg.whack_crash_peer), optarg);
			if (isanyaddr(&msg.whack_crash_peer))
				diagq("0.0.0.0 or 0::0 isn't a valid client address", optarg);
			continue;

		case OPT_LEASES:        /* --leases */
			msg.whack_leases = TRUE;
			continue;

		case OPT_LEASEADDR:     /* --lease-addr <ip-address> */
			msg.whack_lease_ip = optarg;      /* decoded by Pluto */
			continue;

		case OPT_LEASEID:       /* --lease-id <identity> */
			msg.whack_lease_id = optarg;      /* decoded by Pluto */
			continue;

		case OPT_LISTEN:        /* --listen */
			msg.whack_listen = TRUE;
			continue;

		case OPT_UNLISTEN:      /* --unlisten */
			msg.whack_unlisten = TRUE;
			continue;

		case OPT_PURGEOCSP:     /* --purgeocsp */
			msg.whack_purgeocsp = TRUE;
			continue;

		case OPT_REREADSECRETS:   /* --rereadsecrets */
		case OPT_REREADCACERTS:   /* --rereadcacerts */
		case OPT_REREADAACERTS:   /* --rereadaacerts */
		case OPT_REREADOCSPCERTS: /* --rereadocspcerts */
		case OPT_REREADACERTS:    /* --rereadacerts */
		case OPT_REREADCRLS:      /* --rereadcrls */
			msg.whack_reread |= LELEM(c-OPT_REREADSECRETS);
			continue;

		case OPT_REREADALL:     /* --rereadall */
			msg.whack_reread = REREAD_ALL;
			continue;

		case OPT_STATUSALL:     /* --statusall */
			msg.whack_statusall = TRUE;
			/* fall through */

		case OPT_STATUS:        /* --status */
			msg.whack_status = TRUE;
			continue;

		case OPT_SHUTDOWN:      /* --shutdown */
			msg.whack_shutdown = TRUE;
			continue;

		case OPT_OPPO_HERE:     /* --oppohere <ip-address> */
			tunnel_af_used_by = long_opts[long_index].name;
			diagq(ttoaddr(optarg, 0, msg.tunnel_addr_family, &msg.oppo_my_client), optarg);
			if (isanyaddr(&msg.oppo_my_client))
				diagq("0.0.0.0 or 0::0 isn't a valid client address", optarg);
			continue;

		case OPT_OPPO_THERE:    /* --oppohere <ip-address> */
			tunnel_af_used_by = long_opts[long_index].name;
			diagq(ttoaddr(optarg, 0, msg.tunnel_addr_family, &msg.oppo_peer_client), optarg);
			if (isanyaddr(&msg.oppo_peer_client))
				diagq("0.0.0.0 or 0::0 isn't a valid client address", optarg);
			continue;

		case OPT_ASYNC:
			msg.whack_async = TRUE;
			continue;

		/* Smartcard options */

		case SC_ENCRYPT:        /* --scencrypt <plaintext data> */
		case SC_DECRYPT:        /* --scdecrypt <encrypted data> */
			msg.whack_sc_op = 1 + c - SC_ENCRYPT;
			msg.whack_key = FALSE;
			msg.sc_data = optarg;
			continue;

		case SC_INBASE:         /* --inform  <format> */
		case SC_OUTBASE:        /* --outform <format> */
		   {
				int base = 0;

				if (streq(optarg, "16") || strcaseeq(optarg, "hex"))
					base = 16;
				else if (streq(optarg, "64") || strcaseeq(optarg, "base64"))
					base = 64;
				else if (streq(optarg, "256") || strcaseeq(optarg, "text")
					  || strcaseeq(optarg, "ascii"))
					base = 256;
				else
					diagq("not a valid base", optarg);

				if (c == SC_INBASE)
					msg.inbase = base;
				else
					msg.outbase = base;
			}
			continue;

		/* List options */

		case LST_UTC:           /* --utc */
			msg.whack_utc = TRUE;
			continue;

		case LST_ALGS:          /* --listalgs */
		case LST_PUBKEYS:       /* --listpubkeys */
		case LST_CERTS:         /* --listcerts */
		case LST_CACERTS:       /* --listcacerts */
		case LST_ACERTS:        /* --listacerts */
		case LST_AACERTS:       /* --listaacerts */
		case LST_OCSPCERTS:     /* --listocspcerts */
		case LST_GROUPS:        /* --listgroups */
		case LST_CAINFOS:       /* --listcainfos */
		case LST_CRLS:          /* --listcrls */
		case LST_OCSP:          /* --listocsp */
		case LST_CARDS:         /* --listcards */
		case LST_PLUGINS:       /* --listplugins */
			msg.whack_list |= LELEM(c - LST_ALGS);
			continue;

		case LST_ALL:   /* --listall */
			msg.whack_list = LIST_ALL;
			continue;

		/* Connection Description options */

		case END_HOST:  /* --host <ip-address> */
		{
			lset_t new_policy = LEMPTY;

			af_used_by = long_opts[long_index].name;
			diagq(anyaddr(msg.addr_family, &msg.right.host_addr), optarg);
			if (streq(optarg, "%any"))
			{
			}
			else if (streq(optarg, "%opportunistic"))
			{
				/* always use tunnel mode; mark as opportunistic */
				new_policy |= POLICY_TUNNEL | POLICY_OPPO;
			}
			else if (streq(optarg, "%group"))
			{
				/* always use tunnel mode; mark as group */
				new_policy |= POLICY_TUNNEL | POLICY_GROUP;
			}
			else if (streq(optarg, "%opportunisticgroup"))
			{
				/* always use tunnel mode; mark as opportunistic */
				new_policy |= POLICY_TUNNEL | POLICY_OPPO | POLICY_GROUP;
			}
			else
			{
				diagq(ttoaddr(optarg, 0, msg.addr_family
					, &msg.right.host_addr), optarg);
			}

			msg.policy |= new_policy;

			if (new_policy & (POLICY_OPPO | POLICY_GROUP))
			{
				if (!LHAS(end_seen, END_CLIENT - END_FIRST))
				{
					/* set host to 0.0.0 and --client to 0.0.0.0/0
					 * or IPV6 equivalent
					 */
					ip_address any;

					tunnel_af_used_by = optarg;
					diagq(anyaddr(msg.tunnel_addr_family, &any), optarg);
					diagq(initsubnet(&any, 0, '0', &msg.right.client), optarg);
				}
				msg.right.has_client = TRUE;
			}
			if (new_policy & POLICY_GROUP)
			{
				/* client subnet must not be specified by user:
				 * it will come from the group's file.
				 */
				if (LHAS(end_seen, END_CLIENT - END_FIRST))
					diag("--host %group clashes with --client");

				end_seen |= LELEM(END_CLIENT - END_FIRST);
			}
			if (new_policy & POLICY_OPPO)
				msg.right.key_from_DNS_on_demand = TRUE;
			continue;
		}
		case END_ID:    /* --id <identity> */
			msg.right.id = optarg;      /* decoded by Pluto */
			continue;

		case END_CERT:  /* --cert <path> */
			msg.right.cert = optarg;    /* decoded by Pluto */
			continue;

		case END_CA:    /* --ca <distinguished name> */
			msg.right.ca = optarg;      /* decoded by Pluto */
			continue;

		case END_SENDCERT:
			if (streq(optarg, "yes") || streq(optarg, "always"))
			{
				msg.right.sendcert = CERT_ALWAYS_SEND;
			}
			else if (streq(optarg, "no") || streq(optarg, "never"))
			{
				msg.right.sendcert = CERT_NEVER_SEND;
			}
			else if (streq(optarg, "ifasked"))
			{
				msg.right.sendcert = CERT_SEND_IF_ASKED;
			}
			else
			{
				diagq("whack sendcert value is not legal", optarg);
			}
			continue;

		case END_GROUPS:/* --groups <access control groups> */
			msg.right.groups = optarg;  /* decoded by Pluto */
			continue;

		case END_IKEPORT:       /* --ikeport <port-number> */
			if (opt_whole<=0 || opt_whole >= 0x10000)
				diagq("<port-number> must be a number between 1 and 65535", optarg);
			msg.right.host_port = opt_whole;
			continue;

		case END_NEXTHOP:       /* --nexthop <ip-address> */
			af_used_by = long_opts[long_index].name;
			if (streq(optarg, "%direct"))
				diagq(anyaddr(msg.addr_family
					, &msg.right.host_nexthop), optarg);
			else
				diagq(ttoaddr(optarg, 0, msg.addr_family
					, &msg.right.host_nexthop), optarg);
			continue;

		case END_SRCIP:        /* --srcip <ip-address> */
			af_used_by = long_opts[long_index].name;
			if (streq(optarg, "%modeconfig") || streq(optarg, "%modecfg"))
			{
				msg.right.modecfg = TRUE;
			}
			else
			{
				diagq(ttoaddr(optarg, 0, msg.addr_family
					, &msg.right.host_srcip), optarg);
				msg.right.has_srcip = TRUE;
			}
			msg.policy |= POLICY_TUNNEL;        /* srcip => tunnel */
			continue;

		case END_CLIENT:        /* --client <subnet> */
			if (end_seen & LELEM(END_CLIENTWITHIN - END_FIRST))
				diag("--client conflicts with --clientwithin");
			tunnel_af_used_by = long_opts[long_index].name;
			if ((strlen(optarg) >= 6 && strncmp(optarg,"vhost:",6) == 0)
			||  (strlen(optarg) >= 5 && strncmp(optarg,"vnet:",5) == 0))
			{
				msg.right.virt = optarg;
			}
			else
			{
				diagq(ttosubnet(optarg, 0, msg.tunnel_addr_family, &msg.right.client), optarg);
				msg.right.has_client = TRUE;
			}
			msg.policy |= POLICY_TUNNEL;        /* client => tunnel */
			continue;

		case END_CLIENTWITHIN:  /* --clienwithin <address range> */
			if (end_seen & LELEM(END_CLIENT - END_FIRST))
				diag("--clientwithin conflicts with --client");
			tunnel_af_used_by = long_opts[long_index].name;
			diagq(ttosubnet(optarg, 0, msg.tunnel_addr_family, &msg.right.client), optarg);
			msg.right.has_client = TRUE;
			msg.policy |= POLICY_TUNNEL;        /* client => tunnel */
			msg.right.has_client_wildcard = TRUE;
			continue;

		case END_CLIENTPROTOPORT: /* --clientprotoport <protocol>/<port> */
			diagq(ttoprotoport(optarg, 0, &msg.right.protocol, &msg.right.port
				, &msg.right.has_port_wildcard), optarg);
			continue;

		case END_DNSKEYONDEMAND:        /* --dnskeyondemand */
			msg.right.key_from_DNS_on_demand = TRUE;
			continue;

		case END_HOSTACCESS:    /* --hostaccess */
			msg.right.hostaccess = TRUE;
			continue;

		case END_UPDOWN:        /* --updown <updown> */
			msg.right.updown = optarg;
			continue;

		case CD_TO:             /* --to */
			/* process right end, move it to left, reset it */
			if (!LHAS(end_seen, END_HOST - END_FIRST))
				diag("connection missing --host before --to");
			msg.left = msg.right;
			clear_end(&msg.right);
			end_seen_before_to = end_seen;
			end_seen = LEMPTY;
			continue;

		case CD_PSK:            /* --psk */
		case CD_RSASIG:         /* --rsasig */
		case CD_ENCRYPT:        /* --encrypt */
		case CD_AUTHENTICATE:   /* --authenticate */
		case CD_COMPRESS:       /* --compress */
		case CD_TUNNEL:         /* --tunnel */
		case CD_PFS:            /* --pfs */
		case CD_DISABLEARRIVALCHECK:    /* --disablearrivalcheck */
		case CD_DONT_REKEY:     /* --donotrekey */
			msg.policy |= LELEM(c - CD_POLICY_FIRST);
			continue;

		/* --initiateontraffic
		 * --pass
		 * --drop
		 * --reject
		 */
		case CD_SHUNT0:
			msg.policy = (msg.policy & ~POLICY_SHUNT_MASK)
				| ((lset_t)aux << POLICY_SHUNT_SHIFT);
			continue;

		/* --failnone
		 * --failpass
		 * --faildrop
		 * --failreject
		 */
		case CD_FAIL0:
			msg.policy = (msg.policy & ~POLICY_FAIL_MASK)
				| ((lset_t)aux << POLICY_FAIL_SHIFT);
			continue;

		case CD_IKELIFETIME:    /* --ikelifetime <seconds> */
			msg.sa_ike_life_seconds = opt_whole;
			continue;

		case CD_IPSECLIFETIME:  /* --ipseclifetime <seconds> */
			msg.sa_ipsec_life_seconds = opt_whole;
			continue;

		case CD_RKMARGIN:       /* --rekeymargin <seconds> */
			msg.sa_rekey_margin = opt_whole;
			continue;

		case CD_RKFUZZ: /* --rekeyfuzz <percentage> */
			msg.sa_rekey_fuzz = opt_whole;
			continue;

		case CD_KTRIES: /* --keyingtries <count> */
			msg.sa_keying_tries = opt_whole;
			continue;

		case CD_DPDACTION:
			if (streq(optarg, "none"))
				msg.dpd_action = DPD_ACTION_NONE;
			else if (streq(optarg, "clear"))
				msg.dpd_action = DPD_ACTION_CLEAR;
			else if (streq(optarg, "hold"))
				msg.dpd_action = DPD_ACTION_HOLD;
			else if (streq(optarg, "restart"))
				msg.dpd_action = DPD_ACTION_RESTART;
			else
				msg.dpd_action = DPD_ACTION_UNKNOWN;
			continue;

		case CD_DPDDELAY:
			msg.dpd_delay = opt_whole;
			continue;

		case CD_DPDTIMEOUT:
			msg.dpd_timeout = opt_whole;
			continue;

		case CD_IKE:    /* --ike <ike_alg1,ike_alg2,...> */
			msg.ike = optarg;
			continue;

		case CD_PFSGROUP:       /* --pfsgroup modpXXXX */
			msg.pfsgroup = optarg;
			continue;

		case CD_ESP:    /* --esp <esp_alg1,esp_alg2,...> */
			msg.esp = optarg;
			continue;

		case CD_CONNIPV4:
			if (LHAS(cd_seen, CD_CONNIPV6 - CD_FIRST))
				diag("--ipv4 conflicts with --ipv6");

			/* Since this is the default, the flag is redundant.
			 * So we don't need to set msg.addr_family
			 * and we don't need to check af_used_by
			 * and we don't have to consider defaulting tunnel_addr_family.
			 */
			continue;

		case CD_CONNIPV6:
			if (LHAS(cd_seen, CD_CONNIPV4 - CD_FIRST))
				diag("--ipv6 conflicts with --ipv4");

			if (af_used_by != NULL)
				diagq("--ipv6 must precede", af_used_by);

			af_used_by = long_opts[long_index].name;
			msg.addr_family = AF_INET6;

			/* Consider defaulting tunnel_addr_family to AF_INET6.
			 * Do so only if it hasn't yet been specified or used.
			 */
			if (LDISJOINT(cd_seen, LELEM(CD_TUNNELIPV4 - CD_FIRST) | LELEM(CD_TUNNELIPV6 - CD_FIRST))
			&& tunnel_af_used_by == NULL)
				msg.tunnel_addr_family = AF_INET6;
			continue;

		case CD_TUNNELIPV4:
			if (LHAS(cd_seen, CD_TUNNELIPV6 - CD_FIRST))
				diag("--tunnelipv4 conflicts with --tunnelipv6");

			if (tunnel_af_used_by != NULL)
				diagq("--tunnelipv4 must precede", af_used_by);

			msg.tunnel_addr_family = AF_INET;
			continue;

		case CD_TUNNELIPV6:
			if (LHAS(cd_seen, CD_TUNNELIPV4 - CD_FIRST))
				diag("--tunnelipv6 conflicts with --tunnelipv4");

			if (tunnel_af_used_by != NULL)
				diagq("--tunnelipv6 must precede", af_used_by);

			msg.tunnel_addr_family = AF_INET6;
			continue;

		case CA_NAME:           /* --caname <name> */
			msg.name = optarg;
			msg.whack_ca = TRUE;
			continue;
		case CA_CERT:           /* --cacert <path> */
			msg.cacert = optarg;
			continue;
		case CA_LDAPHOST:       /* --ldaphost <hostname> */
			msg.ldaphost = optarg;
			continue;
		case CA_LDAPBASE:       /* --ldapbase <base> */
			msg.ldapbase = optarg;
			continue;
		case CA_CRLURI:         /* --crluri <uri> */
			msg.crluri = optarg;
			continue;
		case CA_CRLURI2:        /* --crluri2 <uri> */
			msg.crluri2 = optarg;
			continue;
		case CA_OCSPURI:        /* --ocspuri <uri> */
			msg.ocspuri = optarg;
			continue;
		case CA_STRICT:         /* --strictcrlpolicy */
			msg.whack_strict = TRUE;
			continue;

#ifdef DEBUG
		case DBGOPT_NONE:       /* --debug-none */
			msg.debugging = DBG_NONE;
			continue;

		case DBGOPT_ALL:        /* --debug-all */
			msg.debugging |= DBG_ALL;   /* note: does not include PRIVATE */
			continue;

		case DBGOPT_RAW:        /* --debug-raw */
		case DBGOPT_CRYPT:      /* --debug-crypt */
		case DBGOPT_PARSING:    /* --debug-parsing */
		case DBGOPT_EMITTING:   /* --debug-emitting */
		case DBGOPT_CONTROL:    /* --debug-control */
		case DBGOPT_LIFECYCLE:  /* --debug-lifecycle */
		case DBGOPT_KERNEL:     /* --debug-kernel, --debug-klips */
		case DBGOPT_DNS:        /* --debug-dns */
		case DBGOPT_NATT:       /* --debug-natt */
		case DBGOPT_OPPO:       /* --debug-oppo */
		case DBGOPT_CONTROLMORE: /* --debug-controlmore */
		case DBGOPT_PRIVATE:    /* --debug-private */
		case DBGOPT_IMPAIR_DELAY_ADNS_KEY_ANSWER:       /* --impair-delay-adns-key-answer */
		case DBGOPT_IMPAIR_DELAY_ADNS_TXT_ANSWER:       /* --impair-delay-adns-txt-answer */
		case DBGOPT_IMPAIR_BUST_MI2:    /* --impair_bust_mi2 */
		case DBGOPT_IMPAIR_BUST_MR2:    /* --impair_bust_mr2 */
			msg.debugging |= LELEM(c-DBGOPT_RAW);
			continue;
#endif
		default:
			assert(FALSE);      /* unknown return value */
		}
		break;
	}

	if (optind != argc)
	{
		/* If you see this message unexpectedly, perhaps the
		 * case for the previous option ended with "break"
		 * instead of "continue"
		 */
		diagq("unexpected argument", argv[optind]);
	}

	/* For each possible form of the command, figure out if an argument
	 * suggests whether that form was intended, and if so, whether all
	 * required information was supplied.
	 */

	/* check opportunistic initiation simulation request */
	switch (opts_seen & (LELEM(OPT_OPPO_HERE) | LELEM(OPT_OPPO_THERE)))
	{
	case LELEM(OPT_OPPO_HERE):
	case LELEM(OPT_OPPO_THERE):
		diag("--oppohere and --oppothere must be used together");
		/*NOTREACHED*/
	case LELEM(OPT_OPPO_HERE) | LELEM(OPT_OPPO_THERE):
		msg.whack_oppo_initiate = TRUE;
		if (LIN(cd_seen, LELEM(CD_TUNNELIPV4 - CD_FIRST) | LELEM(CD_TUNNELIPV6 - CD_FIRST)))
			opts_seen &= ~LELEM(OPT_CD);
		break;
	}

	/* check leases */
	if (LHAS(opts_seen, OPT_LEASEADDR) && LHAS(opts_seen, OPT_LEASEID))
	{
		diag("--lease-addr and --lease-id cannot be used together");
	}

	/* check connection description */
	if (LHAS(opts_seen, OPT_CD))
	{
		if (!LHAS(cd_seen, CD_TO-CD_FIRST))
			diag("connection description option, but no --to");

		if (!LHAS(end_seen, END_HOST-END_FIRST))
			diag("connection missing --host after --to");

		if (isanyaddr(&msg.left.host_addr)
		&& isanyaddr(&msg.right.host_addr))
			diag("hosts cannot both be 0.0.0.0 or 0::0");

		if (msg.policy & POLICY_OPPO)
		{
			if ((msg.policy & (POLICY_PSK | POLICY_PUBKEY)) != POLICY_PUBKEY)
				diag("only PUBKEY is supported for opportunism");
			if ((msg.policy & POLICY_PFS) == 0)
				diag("PFS required for opportunism");
			if ((msg.policy & POLICY_ENCRYPT) == 0)
				diag("encryption required for opportunism");
		}

		check_end(&msg.left, &msg.right, !LHAS(end_seen_before_to, END_NEXTHOP-END_FIRST)
			, msg.addr_family, msg.tunnel_addr_family);

		check_end(&msg.right, &msg.left, !LHAS(end_seen, END_NEXTHOP-END_FIRST)
			, msg.addr_family, msg.tunnel_addr_family);

		if (subnettypeof(&msg.left.client) != subnettypeof(&msg.right.client))
			diag("endpoints clash: one is IPv4 and the other is IPv6");

		if (NEVER_NEGOTIATE(msg.policy))
		{
			/* we think this is just a shunt (because he didn't specify
			 * a host authentication method).  If he didn't specify a
			 * shunt type, he's probably gotten it wrong.
			 */
			if ((msg.policy & POLICY_SHUNT_MASK) == POLICY_SHUNT_TRAP)
				diag("non-shunt connection must have --psk or --rsasig or both");
		}
		else
		{
			/* not just a shunt: a real ipsec connection */
			if ((msg.policy & POLICY_ID_AUTH_MASK) == LEMPTY)
				diag("must specify --rsasig or --psk for a connection");

			if (!HAS_IPSEC_POLICY(msg.policy)
			&& (msg.left.has_client || msg.right.has_client))
				diag("must not specify clients for ISAKMP-only connection");
		}

		msg.whack_connection = TRUE;
	}

	/* decide whether --name is mandatory or forbidden */
	if (!LDISJOINT(opts_seen
	, LELEM(OPT_ROUTE) | LELEM(OPT_UNROUTE)
	| LELEM(OPT_INITIATE) | LELEM(OPT_TERMINATE)
	| LELEM(OPT_DELETE) | LELEM(OPT_CD)))
	{
		if (!LHAS(opts_seen, OPT_NAME) && !msg.whack_ca)
			diag("missing --name <connection_name>");
	}
	else if (!msg.whack_options && !msg.whack_status && !msg.whack_leases)
	{
		if (LHAS(opts_seen, OPT_NAME))
			diag("no reason for --name");
	}

	if (!LDISJOINT(opts_seen, LELEM(OPT_PUBKEYRSA) | LELEM(OPT_ADDKEY)))
	{
		if (!LHAS(opts_seen, OPT_KEYID))
			diag("--addkey and --pubkeyrsa require --keyid");
	}

	if (!(msg.whack_connection || msg.whack_key || msg.whack_myid
	|| msg.whack_delete || msg.whack_deletestate
	|| msg.whack_initiate || msg.whack_oppo_initiate || msg.whack_terminate
	|| msg.whack_route || msg.whack_unroute || msg.whack_listen
	|| msg.whack_unlisten || msg.whack_list || msg.whack_purgeocsp
	|| msg.whack_reread || msg.whack_ca || msg.whack_status
	|| msg.whack_options || msg.whack_shutdown || msg.whack_sc_op
	|| msg.whack_leases))
	{
		diag("no action specified; try --help for hints");
	}

	update_ports(&msg);

	/* tricky quick and dirty check for wild values */
	if (msg.sa_rekey_margin != 0
	&& msg.sa_rekey_fuzz * msg.sa_rekey_margin * 4 / msg.sa_rekey_margin / 4
	 != msg.sa_rekey_fuzz)
		diag("rekeymargin or rekeyfuzz values are so large that they cause oveflow");

	check_life_time (msg.sa_ike_life_seconds, OAKLEY_ISAKMP_SA_LIFETIME_MAXIMUM
		, "ikelifetime", &msg);

	check_life_time(msg.sa_ipsec_life_seconds, SA_LIFE_DURATION_MAXIMUM
		, "ipseclifetime", &msg);

	if (msg.dpd_action == DPD_ACTION_UNKNOWN)
		diag("dpdaction must be \"none\", \"clear\", \"hold\" or \"restart\"");

	if (msg.dpd_action != DPD_ACTION_NONE)
	{
		if (msg.dpd_delay <= 0)
			diag("dpddelay must be larger than zero");

		if (msg.dpd_timeout <= 0)
			diag("dpdtimeout must be larger than zero");

		if (msg.dpd_timeout <= msg.dpd_delay)
			diag("dpdtimeout must be larger than dpddelay");
	}

	/* pack strings for inclusion in message */
	next_str = msg.string;
	str_roof = &msg.string[sizeof(msg.string)];

	/* build esp message as esp="<esp>;<pfsgroup>" */
	if (msg.pfsgroup) {
			snprintf(esp_buf, sizeof (esp_buf), "%s;%s",
					msg.esp ? msg.esp : "",
					msg.pfsgroup ? msg.pfsgroup : "");
			msg.esp=esp_buf;
	}
	if (!pack_str(&msg.name)             /* string  1 */
	||  !pack_str(&msg.left.id)          /* string  2 */
	||  !pack_str(&msg.left.cert)        /* string  3 */
	||  !pack_str(&msg.left.ca)          /* string  4 */
	||  !pack_str(&msg.left.groups)      /* string  5 */
	||  !pack_str(&msg.left.updown)      /* string  6 */
	||  !pack_str(&msg.left.sourceip)    /* string  7 */
	||  !pack_str(&msg.left.virt)        /* string  8 */
	||  !pack_str(&msg.right.id)         /* string  9 */
	||  !pack_str(&msg.right.cert)       /* string 10 */
	||  !pack_str(&msg.right.ca)         /* string 11 */
	||  !pack_str(&msg.right.groups)     /* string 12 */
	||  !pack_str(&msg.right.updown)     /* string 13 */
	||  !pack_str(&msg.right.sourceip)   /* string 14 */
	||  !pack_str(&msg.right.virt)       /* string 15 */
	||  !pack_str(&msg.keyid)            /* string 16 */
	||  !pack_str(&msg.myid)             /* string 17 */
	||  !pack_str(&msg.cacert)           /* string 18 */
	||  !pack_str(&msg.ldaphost)         /* string 19 */
	||  !pack_str(&msg.ldapbase)         /* string 20 */
	||  !pack_str(&msg.crluri)           /* string 21 */
	||  !pack_str(&msg.crluri2)          /* string 22 */
	||  !pack_str(&msg.ocspuri)          /* string 23 */
	||  !pack_str(&msg.ike)              /* string 24 */
	||  !pack_str(&msg.esp)              /* string 25 */
	||  !pack_str(&msg.sc_data)          /* string 26 */
	||  !pack_str(&msg.whack_lease_ip)   /* string 27 */
	||  !pack_str(&msg.whack_lease_id)   /* string 28 */
	||  !pack_str(&msg.xauth_identity)   /* string 29 */
	||  str_roof - next_str < (ptrdiff_t)msg.keyval.len)
		diag("too many bytes of strings to fit in message to pluto");

	memcpy(next_str, msg.keyval.ptr, msg.keyval.len);
	msg.keyval.ptr = NULL;
	next_str += msg.keyval.len;

	msg.magic = ((opts_seen & ~LELEM(OPT_SHUTDOWN))
				| sc_seen | lst_seen | cd_seen | ca_seen) != LEMPTY
			|| msg.whack_options
		? WHACK_MAGIC : WHACK_BASIC_MAGIC;

	/* send message to Pluto */
	if (access(ctl_addr.sun_path, R_OK | W_OK) < 0)
	{
		int e = errno;

		switch (e)
		{
		case EACCES:
			fprintf(stderr, "whack: no right to communicate with pluto (access(\"%s\"))\n"
				, ctl_addr.sun_path);
			break;
		case ENOENT:
			fprintf(stderr, "whack: Pluto is not running (no \"%s\")\n"
				, ctl_addr.sun_path);
			break;
		default:
			fprintf(stderr, "whack: access(\"%s\") failed with %d %s\n"
				, ctl_addr.sun_path, errno, strerror(e));
			break;
		}
		whack_exit(RC_WHACK_PROBLEM);
	}
	else
	{
		int sock = socket(AF_UNIX, SOCK_STREAM, 0);
		int exit_status = 0;
		ssize_t len = next_str - (char *)&msg;

		if (sock == -1)
		{
			int e = errno;

			fprintf(stderr, "whack: socket() failed (%d %s)\n", e, strerror(e));
			whack_exit(RC_WHACK_PROBLEM);
		}

		if (connect(sock, (struct sockaddr *)&ctl_addr
		, offsetof(struct sockaddr_un, sun_path) + strlen(ctl_addr.sun_path)) < 0)
		{
			int e = errno;

			fprintf(stderr, "whack:%s connect() for \"%s\" failed (%d %s)\n"
				, e == ECONNREFUSED? " is Pluto running? " : ""
				, ctl_addr.sun_path, e, strerror(e));
			whack_exit(RC_WHACK_PROBLEM);
		}

		if (write(sock, &msg, len) != len)
		{
			int e = errno;

			fprintf(stderr, "whack: write() failed (%d %s)\n", e, strerror(e));
			whack_exit(RC_WHACK_PROBLEM);
		}

		/* for now, just copy reply back to stdout */

		{
			char buf[4097];     /* arbitrary limit on log line length */
			char *be = buf;

			for (;;)
			{
				char *ls = buf;
				ssize_t rl = read(sock, be, (buf + sizeof(buf)-1) - be);

				if (rl < 0)
				{
					int e = errno;

					fprintf(stderr, "whack: read() failed (%d %s)\n", e, strerror(e));
					whack_exit(RC_WHACK_PROBLEM);
				}
				if (rl == 0)
				{
					if (be != buf)
						fprintf(stderr, "whack: last line from pluto too long or unterminated\n");
					break;
				}

				be += rl;
				*be = '\0';

				for (;;)
				{
					char *le = strchr(ls, '\n');

					if (le == NULL)
					{
						/* move last, partial line to start of buffer */
						memmove(buf, ls, be-ls);
						be -= ls - buf;
						break;
					}

					le++;       /* include NL in line */
					ignore_result(write(1, ls, le - ls));

					/* figure out prefix number
					 * and how it should affect our exit status
					 */
					{
						unsigned long s = strtoul(ls, NULL, 10);

						switch (s)
						{
						case RC_COMMENT:
						case RC_LOG:
							/* ignore */
							break;
						case RC_SUCCESS:
							/* be happy */
							exit_status = 0;
							break;
						case RC_ENTERSECRET:
							get_secret(sock);
							break;
						/* case RC_LOG_SERIOUS: */
						default:
							/* pass through */
							exit_status = s;
							break;
						}
					}
					ls = le;
				}
			}
		}
		whack_exit(exit_status);
	}
	return -1; /* should never be reached */
}

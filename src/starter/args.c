/* automatic handling of confread struct arguments
 * Copyright (C) 2006 Andreas Steffen
 * Hochschule fuer Technik Rapperswil, Switzerland
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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <library.h>
#include <utils/debug.h>

#include "keywords.h"
#include "confread.h"
#include "args.h"

/* argument types */

typedef enum {
	ARG_NONE,
	ARG_ENUM,
	ARG_UINT,
	ARG_TIME,
	ARG_ULNG,
	ARG_ULLI,
	ARG_UBIN,
	ARG_PCNT,
	ARG_STR,
	ARG_LST,
	ARG_MISC
} arg_t;

/* various keyword lists */

static const char *LST_bool[] = {
	"no",
	"yes",
	 NULL
};

static const char *LST_sendcert[] = {
	"always",
	"ifasked",
	"never",
	"yes",
	"no",
	 NULL
};

static const char *LST_unique[] = {
	"no",
	"yes",
	"replace",
	"keep",
	"never",
	 NULL
};

static const char *LST_strict[] = {
	"no",
	"yes",
	"ifuri",
	 NULL
};
static const char *LST_dpd_action[] = {
	"none",
	"clear",
	"hold",
	"restart",
	 NULL
};

static const char *LST_startup[] = {
	"ignore",
	"add",
	"route",
	"start",
	 NULL
};

static const char *LST_keyexchange[] = {
	"ike",
	"ikev1",
	"ikev2",
	 NULL
};

static const char *LST_authby[] = {
	"psk",
	"secret",
	"pubkey",
	"rsa",
	"rsasig",
	"ecdsa",
	"ecdsasig",
	"xauthpsk",
	"xauthrsasig",
	"never",
	 NULL
};

static const char *LST_fragmentation[] = {
	"no",
	"yes",
	"force",
	 NULL
};

typedef struct {
	arg_t       type;
	size_t      offset;
	const char  **list;
} token_info_t;

static const token_info_t token_info[] =
{
	/* config setup keywords */
	{ ARG_STR,  offsetof(starter_config_t, setup.charondebug),  NULL               },
	{ ARG_ENUM, offsetof(starter_config_t, setup.uniqueids), LST_unique            },
	{ ARG_ENUM, offsetof(starter_config_t, setup.cachecrls), LST_bool              },
	{ ARG_ENUM, offsetof(starter_config_t, setup.strictcrlpolicy), LST_strict      },
	{ ARG_MISC, 0, NULL  /* KW_PKCS11_DEPRECATED */                                },
	{ ARG_MISC, 0, NULL  /* KW_SETUP_DEPRECATED */                                 },

	/* conn section keywords */
	{ ARG_STR,  offsetof(starter_conn_t, name), NULL                               },
	{ ARG_ENUM, offsetof(starter_conn_t, startup), LST_startup                     },
	{ ARG_ENUM, offsetof(starter_conn_t, keyexchange), LST_keyexchange             },
	{ ARG_MISC, 0, NULL  /* KW_TYPE */                                             },
	{ ARG_MISC, 0, NULL  /* KW_COMPRESS */                                         },
	{ ARG_ENUM, offsetof(starter_conn_t, install_policy), LST_bool                 },
	{ ARG_ENUM, offsetof(starter_conn_t, aggressive), LST_bool                     },
	{ ARG_STR,  offsetof(starter_conn_t, authby), LST_authby                       },
	{ ARG_STR,  offsetof(starter_conn_t, eap_identity), NULL                       },
	{ ARG_STR,  offsetof(starter_conn_t, aaa_identity), NULL                       },
	{ ARG_MISC, 0, NULL  /* KW_MOBIKE */                                           },
	{ ARG_MISC, 0, NULL  /* KW_FORCEENCAPS */                                      },
	{ ARG_ENUM, offsetof(starter_conn_t, fragmentation), LST_fragmentation         },
	{ ARG_UBIN, offsetof(starter_conn_t, ikedscp), NULL                            },
	{ ARG_TIME, offsetof(starter_conn_t, sa_ike_life_seconds), NULL                },
	{ ARG_TIME, offsetof(starter_conn_t, sa_ipsec_life_seconds), NULL              },
	{ ARG_TIME, offsetof(starter_conn_t, sa_rekey_margin), NULL                    },
	{ ARG_ULLI, offsetof(starter_conn_t, sa_ipsec_life_bytes), NULL                },
	{ ARG_ULLI, offsetof(starter_conn_t, sa_ipsec_margin_bytes), NULL              },
	{ ARG_ULLI, offsetof(starter_conn_t, sa_ipsec_life_packets), NULL              },
	{ ARG_ULLI, offsetof(starter_conn_t, sa_ipsec_margin_packets), NULL            },
	{ ARG_MISC, 0, NULL  /* KW_KEYINGTRIES */                                      },
	{ ARG_PCNT, offsetof(starter_conn_t, sa_rekey_fuzz), NULL                      },
	{ ARG_MISC, 0, NULL  /* KW_REKEY */                                            },
	{ ARG_MISC, 0, NULL  /* KW_REAUTH */                                           },
	{ ARG_STR,  offsetof(starter_conn_t, ike), NULL                                },
	{ ARG_STR,  offsetof(starter_conn_t, esp), NULL                                },
	{ ARG_STR,  offsetof(starter_conn_t, ah), NULL                                 },
	{ ARG_TIME, offsetof(starter_conn_t, dpd_delay), NULL                          },
	{ ARG_TIME, offsetof(starter_conn_t, dpd_timeout), NULL                        },
	{ ARG_ENUM, offsetof(starter_conn_t, dpd_action), LST_dpd_action               },
	{ ARG_ENUM, offsetof(starter_conn_t, close_action), LST_dpd_action             },
	{ ARG_TIME, offsetof(starter_conn_t, inactivity), NULL                         },
	{ ARG_MISC, 0, NULL  /* KW_MODECONFIG */                                       },
	{ ARG_MISC, 0, NULL  /* KW_XAUTH */                                            },
	{ ARG_STR,  offsetof(starter_conn_t, xauth_identity), NULL                     },
	{ ARG_ENUM, offsetof(starter_conn_t, me_mediation), LST_bool                   },
	{ ARG_STR,  offsetof(starter_conn_t, me_mediated_by), NULL                     },
	{ ARG_STR,  offsetof(starter_conn_t, me_peerid), NULL                          },
	{ ARG_UINT, offsetof(starter_conn_t, reqid), NULL                              },
	{ ARG_MISC, 0, NULL  /* KW_MARK */                                             },
	{ ARG_MISC, 0, NULL  /* KW_MARK_IN */                                          },
	{ ARG_MISC, 0, NULL  /* KW_MARK_OUT */                                         },
	{ ARG_MISC, 0, NULL  /* KW_TFC */                                              },
	{ ARG_MISC, 0, NULL  /* KW_PFS_DEPRECATED */                                   },
	{ ARG_MISC, 0, NULL  /* KW_CONN_DEPRECATED */                                  },

	/* ca section keywords */
	{ ARG_STR,  offsetof(starter_ca_t, name), NULL                                 },
	{ ARG_ENUM, offsetof(starter_ca_t, startup), LST_startup                       },
	{ ARG_STR,  offsetof(starter_ca_t, cacert), NULL                               },
	{ ARG_STR,  offsetof(starter_ca_t, crluri), NULL                               },
	{ ARG_STR,  offsetof(starter_ca_t, crluri2), NULL                              },
	{ ARG_STR,  offsetof(starter_ca_t, ocspuri), NULL                              },
	{ ARG_STR,  offsetof(starter_ca_t, ocspuri2), NULL                             },
	{ ARG_STR,  offsetof(starter_ca_t, certuribase), NULL                          },
	{ ARG_MISC, 0, NULL  /* KW_CA_DEPRECATED */                                    },

	/* end keywords */
	{ ARG_STR,  offsetof(starter_end_t, host), NULL                                },
	{ ARG_UINT, offsetof(starter_end_t, ikeport), NULL                             },
	{ ARG_STR,  offsetof(starter_end_t, subnet), NULL                              },
	{ ARG_MISC, 0, NULL  /* KW_PROTOPORT */                                        },
	{ ARG_STR,  offsetof(starter_end_t, sourceip), NULL                            },
	{ ARG_STR,  offsetof(starter_end_t, dns), NULL                                 },
	{ ARG_ENUM, offsetof(starter_end_t, firewall), LST_bool                        },
	{ ARG_ENUM, offsetof(starter_end_t, hostaccess), LST_bool                      },
	{ ARG_ENUM, offsetof(starter_end_t, allow_any), LST_bool                       },
	{ ARG_STR,  offsetof(starter_end_t, updown), NULL                              },
	{ ARG_STR,  offsetof(starter_end_t, auth), NULL                                },
	{ ARG_STR,  offsetof(starter_end_t, auth2), NULL                               },
	{ ARG_STR,  offsetof(starter_end_t, id), NULL                                  },
	{ ARG_STR,  offsetof(starter_end_t, id2), NULL                                 },
	{ ARG_STR,  offsetof(starter_end_t, rsakey), NULL                              },
	{ ARG_STR,  offsetof(starter_end_t, cert), NULL                                },
	{ ARG_STR,  offsetof(starter_end_t, cert2), NULL                               },
	{ ARG_STR,  offsetof(starter_end_t, cert_policy), NULL                         },
	{ ARG_ENUM, offsetof(starter_end_t, sendcert), LST_sendcert                    },
	{ ARG_STR,  offsetof(starter_end_t, ca), NULL                                  },
	{ ARG_STR,  offsetof(starter_end_t, ca2), NULL                                 },
	{ ARG_STR,  offsetof(starter_end_t, groups), NULL                              },
	{ ARG_STR,  offsetof(starter_end_t, groups2), NULL                             },
	{ ARG_MISC, 0, NULL  /* KW_END_DEPRECATED */                                   },
};

static void free_list(char **list)
{
	char **s;

	for (s = list; *s; s++)
	{
		free(*s);
	}
	free(list);
}

char** new_list(char *value)
{
	char *val, *b, *e, *end, **ret;
	int count;

	val = strdupnull(value);
	if (!val)
	{
		return NULL;
	}
	end = val + strlen(val);
	for (b = val, count = 0; b < end;)
	{
		for (e = b; ((*e != ' ') && (*e != '\0')); e++);
		*e = '\0';
		if (e != b)
		{
			count++;
		}
		b = e + 1;
	}
	if (count == 0)
	{
		free(val);
		return NULL;
	}
	ret = (char **)malloc((count+1) * sizeof(char *));

	for (b = val, count = 0; b < end; )
	{
		for (e = b; (*e != '\0'); e++);
		if (e != b)
		{
			ret[count++] = strdupnull(b);
		}
		b = e + 1;
	}
	ret[count] = NULL;
	free(val);
	return ret;
}


/*
 * assigns an argument value to a struct field
 */
bool assign_arg(kw_token_t token, kw_token_t first, kw_list_t *kw, char *base,
				bool *assigned)
{
	char *p = base + token_info[token].offset;
	const char **list = token_info[token].list;

	int index = -1;  /* used for enumeration arguments */

	seen_t *seen = (seen_t*)base; /* seen flags are at the top of the struct */

	*assigned = FALSE;

	DBG3(DBG_APP, "  %s=%s", kw->entry->name, kw->value);

	if (*seen & SEEN_KW(token, first))
	{
		DBG1(DBG_APP, "# duplicate '%s' option", kw->entry->name);
		return FALSE;
	}

	if (token == KW_ESP || token == KW_AH)
	{
		if (*seen & (SEEN_KW(KW_ESP, first) | SEEN_KW(KW_AH, first)))
		{
			DBG1(DBG_APP, "# can't have both 'ah' and 'esp' options");
			return FALSE;
		}
	}

	/* set flag that this argument has been seen */
	*seen |= SEEN_KW(token, first);

	/* is there a keyword list? */
	if (list != NULL && token_info[token].type != ARG_LST)
	{
		bool match = FALSE;

		while (*list != NULL && !match)
		{
			index++;
			match = streq(kw->value, *list++);
		}
		if (!match)
		{
			DBG1(DBG_APP, "# bad value: %s=%s", kw->entry->name, kw->value);
			return FALSE;
		}
	}

	switch (token_info[token].type)
	{
	case ARG_NONE:
		DBG1(DBG_APP, "# option '%s' not supported yet", kw->entry->name);
		return FALSE;
	case ARG_ENUM:
		{
			if (index < 0)
			{
				DBG1(DBG_APP, "# bad enumeration value: %s=%s (%d)",
					 kw->entry->name, kw->value, index);
				return FALSE;
			}

			if (token_info[token].list == LST_bool)
			{
				bool *b = (bool *)p;
				*b = (index > 0);
			}
			else
			{
				int *i = (int *)p;
				*i = index;
			}
		}
		break;

	case ARG_UINT:
		{
			char *endptr;
			u_int *u = (u_int *)p;

			*u = strtoul(kw->value, &endptr, 10);

			if (*endptr != '\0')
			{
				DBG1(DBG_APP, "# bad integer value: %s=%s", kw->entry->name,
					 kw->value);
				return FALSE;
			}
		}
		break;
	case ARG_ULNG:
	case ARG_PCNT:
		{
			char *endptr;
			unsigned long *l = (unsigned long *)p;

			*l = strtoul(kw->value, &endptr, 10);

			if (token_info[token].type == ARG_ULNG)
			{
				if (*endptr != '\0')
				{
					DBG1(DBG_APP, "# bad integer value: %s=%s", kw->entry->name,
						 kw->value);
					return FALSE;
				}
			}
			else
			{
				if ((*endptr != '%') || (endptr[1] != '\0') || endptr == kw->value)
				{
					DBG1(DBG_APP, "# bad percent value: %s=%s", kw->entry->name,
						 kw->value);
					return FALSE;
				}
			}

		}
		break;
	case ARG_ULLI:
		{
			char *endptr;
			unsigned long long *ll = (unsigned long long *)p;

			*ll = strtoull(kw->value, &endptr, 10);

			if (*endptr != '\0')
			{
				DBG1(DBG_APP, "# bad integer value: %s=%s", kw->entry->name,
					 kw->value);
				return FALSE;
			}
		}
		break;
	case ARG_UBIN:
		{
			char *endptr;
			u_int *u = (u_int *)p;

			*u = strtoul(kw->value, &endptr, 2);

			if (*endptr != '\0')
			{
				DBG1(DBG_APP, "# bad binary value: %s=%s", kw->entry->name,
					 kw->value);
				return FALSE;
			}
		}
		break;
	case ARG_TIME:
		{
			char *endptr;
			time_t *t = (time_t *)p;

			*t = strtoul(kw->value, &endptr, 10);

			/* time in seconds? */
			if (*endptr == '\0' || (*endptr == 's' && endptr[1] == '\0'))
			{
				break;
			}
			if (endptr[1] == '\0')
			{
				if (*endptr == 'm')  /* time in minutes? */
				{
					*t *= 60;
					break;
				}
				if (*endptr == 'h')  /* time in hours? */
				{
					*t *= 3600;
					break;
				}
				if (*endptr == 'd')  /* time in days? */
				{
					*t *= 3600*24;
					break;
				}
			}
			DBG1(DBG_APP, "# bad duration value: %s=%s", kw->entry->name,
				 kw->value);
			return FALSE;
		}
	case ARG_STR:
		{
			char **cp = (char **)p;

			/* free any existing string */
			free(*cp);

			/* assign the new string */
			*cp = strdupnull(kw->value);
		}
		break;
	case ARG_LST:
		{
			char ***listp = (char ***)p;

			/* free any existing list */
			if (*listp != NULL)
			{
				free_list(*listp);
			}
			/* create a new list and assign values */
			*listp = new_list(kw->value);

			/* is there a keyword list? */
			if (list != NULL)
			{
				char ** lst;

				for (lst = *listp; lst && *lst; lst++)
				{
					bool match = FALSE;

					list = token_info[token].list;

					while (*list != NULL && !match)
					{
						match = streq(*lst, *list++);
					}
					if (!match)
					{
						DBG1(DBG_APP, "# bad value: %s=%s",
							 kw->entry->name, *lst);
						return FALSE;
					}
				}
			}
		}
		/* fall through */
	default:
		return TRUE;
	}

	*assigned = TRUE;
	return TRUE;
}

/*
 *  frees all dynamically allocated arguments in a struct
 */
void free_args(kw_token_t first, kw_token_t last, char *base)
{
	kw_token_t token;

	for (token = first; token <= last; token++)
	{
		char *p = base + token_info[token].offset;

		switch (token_info[token].type)
		{
		case ARG_STR:
			{
				char **cp = (char **)p;

				free(*cp);
				*cp = NULL;
			}
			break;
		case ARG_LST:
			{
				char ***listp = (char ***)p;

				if (*listp != NULL)
				{
					free_list(*listp);
					*listp = NULL;
				 }
			}
			break;
		default:
			break;
		}
	}
}

/*
 *  clone all dynamically allocated arguments in a struct
 */
void clone_args(kw_token_t first, kw_token_t last, char *base1, char *base2)
{
	kw_token_t token;

	for (token = first; token <= last; token++)
	{
		if (token_info[token].type == ARG_STR)
		{
			char **cp1 = (char **)(base1 + token_info[token].offset);
			char **cp2 = (char **)(base2 + token_info[token].offset);

			*cp1 = strdupnull(*cp2);
		}
	}
}

static bool cmp_list(char **list1, char **list2)
{
	if ((list1 == NULL) && (list2 == NULL))
	{
		return TRUE;
	}
	if ((list1 == NULL) || (list2 == NULL))
	{
		return FALSE;
	}

	for ( ; *list1 && *list2; list1++, list2++)
	{
		if (strcmp(*list1,*list2) != 0)
		{
			return FALSE;
		}
	}

	if ((*list1 != NULL) || (*list2 != NULL))
	{
		return FALSE;
	}

	return TRUE;
}

/*
 *  compare all arguments in a struct
 */
bool cmp_args(kw_token_t first, kw_token_t last, char *base1, char *base2)
{
	kw_token_t token;

	for (token = first; token <= last; token++)
	{
		char *p1 = base1 + token_info[token].offset;
		char *p2 = base2 + token_info[token].offset;

		switch (token_info[token].type)
		{
		case ARG_ENUM:
			if (token_info[token].list == LST_bool)
			{
				bool *b1 = (bool *)p1;
				bool *b2 = (bool *)p2;

				if (*b1 != *b2)
				{
					return FALSE;
				}
			}
			else
			{
				int *i1 = (int *)p1;
				int *i2 = (int *)p2;

				if (*i1 != *i2)
				{
					return FALSE;
				}
			}
			break;
		case ARG_UINT:
			{
				u_int *u1 = (u_int *)p1;
				u_int *u2 = (u_int *)p2;

				if (*u1 != *u2)
				{
					return FALSE;
				}
			}
			break;
		case ARG_ULNG:
		case ARG_PCNT:
			{
				unsigned long *l1 = (unsigned long *)p1;
				unsigned long *l2 = (unsigned long *)p2;

				if (*l1 != *l2)
				{
					return FALSE;
				}
			}
			break;
		case ARG_ULLI:
			{
				unsigned long long *ll1 = (unsigned long long *)p1;
				unsigned long long *ll2 = (unsigned long long *)p2;

				if (*ll1 != *ll2)
				{
					return FALSE;
				}
			}
			break;
		case ARG_TIME:
			{
				time_t *t1 = (time_t *)p1;
				time_t *t2 = (time_t *)p2;

				if (*t1 != *t2)
				{
					return FALSE;
				}
			}
			break;
		case ARG_STR:
			{
				char **cp1 = (char **)p1;
				char **cp2 = (char **)p2;

				if (*cp1 == NULL && *cp2 == NULL)
				{
					break;
				}
				if (*cp1 == NULL || *cp2 == NULL || strcmp(*cp1, *cp2) != 0)
				{
					return FALSE;
				}
			}
			break;
		case ARG_LST:
			{
				char ***listp1 = (char ***)p1;
				char ***listp2 = (char ***)p2;

				if (!cmp_list(*listp1, *listp2))
				{
					return FALSE;
				}
			}
			break;
		default:
			break;
		}
	}
	return TRUE;
}

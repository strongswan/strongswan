/* strongSwan KLIPS starter
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
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
 *
 * RCSID $Id: klips.c,v 1.8 2006/02/15 18:33:57 as Exp $
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>

#include <freeswan.h>

#include "../pluto/constants.h"
#include "../pluto/defs.h"
#include "../pluto/log.h"

#include "confread.h"
#include "klips.h"
#include "files.h"
#include "exec.h"

static int _klips_module_loaded = 0;

bool
starter_klips_init(void)
{
    struct stat stb;

    if (stat(PROC_IPSECVERSION, &stb) != 0)
    {
	if (stat(PROC_MODULES, &stb) == 0)
	{
	    unsetenv("MODPATH");
	    unsetenv("MODULECONF");
	    system("depmod -a >/dev/null 2>&1");
	    system("modprobe -qv ipsec");
	}
	if (stat(PROC_IPSECVERSION, &stb) == 0)
	{
	    _klips_module_loaded = 1;
	}
	else
	{
	    DBG(DBG_CONTROL,
		DBG_log("kernel appears to lack KLIPS")
	    )
	    return FALSE;
	}
    }

    /* make sure that all available crypto algorithms are loaded */
    if (stat(PROC_MODULES, &stb) == 0)
    {
	system("modprobe -qv ipsec_aes");
	system("modprobe -qv ipsec_serpent");
	system("modprobe -qv ipsec_twofish");
	system("modprobe -qv ipsec_blowfish");
	system("modprobe -qv ipsec_sha2");
    }

    starter_klips_clear();

    DBG(DBG_CONTROL,
	DBG_log("Found KLIPS IPsec stack")
    )
    return TRUE;
}

static void
_sysflags (char *name, int value)
{
    int res = starter_exec("echo %d >%s/%s 2>/dev/null"
			, value? 1 : 0, PROC_SYSFLAGS, name);

    if (res)
	plog("can't set sysflag %s to %d", name, value? 1 : 0);
}

void
starter_klips_set_config(starter_config_t *cfg)
{
    char **l;

    _sysflags("icmp", cfg->setup.fragicmp);
    _sysflags("inbound_policy_check", 1);
    /* _sysflags("no_eroute_pass", 0); */
    /* _sysflags("opportunistic", 0);  */
    _sysflags("tos", cfg->setup.hidetos);

    starter_exec("%s/klipsdebug --none", IPSEC_EXECDIR);
    for (l = cfg->setup.klipsdebug; l && *l; l++)
    {
	if ((streq(*l, "none")) || (streq(*l, "all")))
	    starter_exec("%s/klipsdebug --%s", IPSEC_EXECDIR, *l);
	else
	    starter_exec("%s/klipsdebug --set %s", IPSEC_EXECDIR, *l);
    }

    starter_exec("%s/eroute --del --eraf inet --src 0/0 --dst 0/0 2>/dev/null"
		, IPSEC_EXECDIR);
    starter_exec("%s/eroute --label packetdefault --replace --eraf inet "
		 "--src 0/0 --dst 0/0 --said %%%s", IPSEC_EXECDIR
		, cfg->setup.packetdefault ? cfg->setup.packetdefault : "drop");
}

void
starter_klips_clear(void)
{
    system(IPSEC_EXECDIR"/eroute --clear");
    system(IPSEC_EXECDIR"/spi --clear");
    system(IPSEC_EXECDIR"/klipsdebug --none");
}

void
starter_klips_cleanup(void)
{
    starter_klips_clear();
    if (_klips_module_loaded)
    {
	system("rmmod ipsec");
	_klips_module_loaded = 0;
    }
}

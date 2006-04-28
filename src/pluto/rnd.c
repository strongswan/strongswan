/* randomness machinery
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
 *
 * RCSID $Id: rnd.c,v 1.3 2005/09/08 16:26:30 as Exp $
 */

/* A true random number generator (we hope)
 *
 * Under LINUX ("linux" predefined), use /dev/urandom.
 * Under OpenBSD ("__OpenBSD__" predefined), use arc4random().
 * Otherwise use our own random number generator based on clock skew.
 *   I (ADK) first heard of the idea from John Ioannidis, who heard it
 *   from Matt Blaze and/or Jack Lacy.
 * ??? Why is mixing need for linux but not OpenBSD?
 */

/* Pluto's uses of randomness:
 *
 * - Setting up the "secret_of_the_day".  This changes every hour!  20
 *   bytes a shot.  It is used in building responder cookies.
 *
 * - generating initiator cookies (8 bytes, once per Phase 1 initiation).
 *
 * - 32 bytes per DH local secret.  Once per Main Mode exchange and once
 *   per Quick Mode Exchange with PFS.  (Size is our choice, with
 *   tradeoffs.)
 *
 * - 16 bytes per nonce we generate.  Once per Main Mode exchange and
 *   once per Quick Mode exchange.  (Again, we choose the size.)
 *
 * - 4 bytes per SPI number that we generate.  We choose the SPIs for all
 *   inbound SPIs, one to three per IPSEC SA (one for AH (rare, probably)
 *   one for ESP (almost always), and one for tunnel (very common)).
 *   I don't actually know how the kernel would generate these numbers --
 *   currently Pluto generates them; this isn't the way things will be
 *   done in the future.
 *
 * - 4 bytes per Message ID we need to generate.  One per Quick Mode
 *   exchange.  Eventually, one per informational exchange.
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <fcntl.h>

#include <freeswan.h>

#include "sha1.h"
#include "constants.h"
#include "defs.h"
#include "rnd.h"
#include "log.h"
#include "timer.h"

#ifdef linux
# define USE_DEV_RANDOM	1
# define RANDOM_PATH    "/dev/urandom"
#else
# ifdef __OpenBSD__
#  define USE_ARC4RANDOM
# else
#   define USE_CLOCK_SLEW
# endif
#endif

#ifdef USE_ARC4RANDOM

#define get_rnd_byte() (arc4random() % 256)

#else	/**** start of large #else ****/

#ifdef USE_DEV_RANDOM
static int random_fd = NULL_FD;
#endif

#define RANDOM_POOL_SIZE   SHA1_DIGEST_SIZE
static u_char random_pool[RANDOM_POOL_SIZE];

#ifdef USE_DEV_RANDOM

/* Generate (what we hope is) a true random byte using /dev/urandom  */
static u_char
generate_rnd_byte(void)
{
    u_char c;

    if (read(random_fd, &c, sizeof(c)) == -1)
	exit_log_errno((e, "read() failed in get_rnd_byte()"));

    return c;
}

#else /* !USE_DEV_RANDOM */

/* Generate (what we hope is) a true random byte using the clock skew trick.
 * Note: this code is not maintained!  In particular, LINUX signal(2)
 * semantics changed with glibc2 (and not for the better).  It isn't clear
 * that this code will work.  We keep the code because someday it might
 * come in handy.
 */
# error "This code is not maintained.  Please define USE_DEV_RANDOM."

static volatile sig_atomic_t i, j, k;

/* timer signal handler */
static void
rnd_handler(int ignore_me UNUSED)
{
    k <<= 1;	/* Shift left by 1 */
    j++;
    k |= (i & 0x1); /* Get lsbit of counter */

    if (j != 8)
	signal(SIGVTALRM, rnd_handler);
}

static u_char
generate_rnd_byte(void)
{
    struct itimerval tmval, ntmval;

# ifdef NEVER	/* ??? */
#  ifdef linux
    int mask = siggetmask();

    mask |= SIGVTALRM;
    sigsetmask(mask);
#  endif
# endif

    i = 0;
    j = 0;

    ntmval.it_interval.tv_sec = 0;
    ntmval.it_interval.tv_usec = 1;
    ntmval.it_value.tv_sec = 0;
    ntmval.it_value.tv_usec = 1;
    signal(SIGVTALRM, rnd_handler);
    setitimer(ITIMER_VIRTUAL, &ntmval, &tmval);

    while (j != 8)
	i++;

    setitimer(ITIMER_VIRTUAL, &tmval, &ntmval);
    signal(SIGVTALRM, SIG_IGN);

# ifdef NEVER	/* ??? */
#  ifdef linux
    mask ^= SIGVTALRM;
    sigsetmask(mask);
#  endif
# endif

    return k;
}

#endif /* !USE_DEV_RANDOM */

static void
mix_pool(void)
{
    SHA1_CTX ctx;

    SHA1Init(&ctx);
    SHA1Update(&ctx, random_pool, RANDOM_POOL_SIZE);
    SHA1Final(random_pool, &ctx);
}

/*
 * Get a single random byte.
 */
static u_char
get_rnd_byte(void)
{
    random_pool[RANDOM_POOL_SIZE - 1] = generate_rnd_byte();
    random_pool[0] = generate_rnd_byte();
    mix_pool();
    return random_pool[0];
}

#endif /* !USE_ARC4RANDOM */	/**** end of large #else ****/

void
get_rnd_bytes(u_char *buffer, int length)
{
    int i;

    for (i = 0; i < length; i++)
	buffer[i] = get_rnd_byte();
}

/*
 * Initialize the random pool.
 */
void
init_rnd_pool(void)
{
#ifndef USE_ARC4RANDOM
# ifdef USE_DEV_RANDOM
    DBG(DBG_KLIPS, DBG_log("opening %s", RANDOM_PATH));
    random_fd = open(RANDOM_PATH, O_RDONLY);
    if (random_fd == -1)
	exit_log_errno((e, "open of %s failed in init_rnd_pool()", RANDOM_PATH));
    fcntl(random_fd, F_SETFD, FD_CLOEXEC);
# endif

    get_rnd_bytes(random_pool, RANDOM_POOL_SIZE);
    mix_pool();
#endif /* !USE_ARC4RANDOM */

    /* start of rand(3) on the right foot */
    {
	unsigned int seed;

	get_rnd_bytes((void *)&seed, sizeof(seed));
	srand(seed);
    }
}

u_char    secret_of_the_day[SHA1_DIGEST_SIZE];

#ifndef NO_PLUTO

void
init_secret(void)
{
    /*
     * Generate the secret value for responder cookies, and
     * schedule an event for refresh.
     */
    get_rnd_bytes(secret_of_the_day, sizeof(secret_of_the_day));
    event_schedule(EVENT_REINIT_SECRET, EVENT_REINIT_SECRET_DELAY, NULL);
}

#endif /* NO_PLUTO */

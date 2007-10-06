/* misc. universal things
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
 * RCSID $Id$
 */

#ifndef _DEFS_H
#define _DEFS_H

#include <sys/types.h>

#ifdef KLIPS
# define USED_BY_KLIPS	/* ignore */
#else
# define USED_BY_KLIPS	UNUSED
#endif

#ifdef DEBUG
# define USED_BY_DEBUG	/* ignore */
#else
# define USED_BY_DEBUG	UNUSED
#endif

/* Length of temporary buffers */

#define BUF_LEN	      512

/* type of serial number of a state object
 * Needed in connections.h and state.h; here to simplify dependencies.
 */
typedef unsigned long so_serial_t;
#define SOS_NOBODY	0	/* null serial number */
#define SOS_FIRST	1	/* first normal serial number */

/* memory allocation */

extern void *alloc_bytes(size_t size, const char *name);
#define alloc_thing(thing, name) (alloc_bytes(sizeof(thing), (name)))

extern void *clone_bytes(const void *orig, size_t size, const char *name);
#define clone_thing(orig, name) clone_bytes((const void *)&(orig), sizeof(orig), (name))
#define clone_str(str, name) \
    ((str) == NULL? NULL : clone_bytes((str), strlen((str))+1, (name)))

#ifdef LEAK_DETECTIVE
  extern void pfree(void *ptr);
  extern void report_leaks(void);
#else
# define pfree(ptr) free(ptr)	/* ordinary stdc free */
#endif
#define pfreeany(p) { if ((p) != NULL) pfree(p); }
#define replace(p, q) { pfreeany(p); (p) = (q); }


/* chunk is a simple pointer-and-size abstraction */

struct chunk {
    u_char *ptr;
    size_t len;
    };
typedef struct chunk chunk_t;

#define setchunk(ch, addr, size) { (ch).ptr = (addr); (ch).len = (size); }
#define strchunk(str) { str, sizeof(str) }
/* NOTE: freeanychunk, unlike pfreeany, NULLs .ptr */
#define freeanychunk(ch) { pfreeany((ch).ptr); (ch).ptr = NULL; }
#define clonetochunk(ch, addr, size, name) \
    { (ch).ptr = clone_bytes((addr), (ch).len = (size), name); }
#define clonereplacechunk(ch, addr, size, name) \
    { pfreeany((ch).ptr); clonetochunk(ch, addr, size, name); }
#define chunkcpy(dst, chunk) \
    { memcpy(dst, chunk.ptr, chunk.len); dst += chunk.len;}
#define same_chunk(a, b) \
    ( (a).len == (b).len && memcmp((a).ptr, (b).ptr, (b).len) == 0 )

extern char* temporary_cyclic_buffer(void);
extern const char* concatenate_paths(const char *a, const char *b);

extern const chunk_t empty_chunk;

/* compare two chunks */
extern int cmp_chunk(chunk_t a, chunk_t b);

/* move a chunk to a memory position and free it after insertion */
extern void mv_chunk(u_char **pos, chunk_t content);

/* write the binary contents of a chunk_t to a file */
extern bool write_chunk(const char *filename, const char *label, chunk_t ch
    ,mode_t mask, bool force);

/* display a date either in local or UTC time */
extern char* timetoa(const time_t *time, bool utc);

/* warns a predefined interval before expiry */
extern const char* check_expiry(time_t expiration_date,
    int warning_interval, bool strict);

#define MAX_PROMPT_PASS_TRIALS	5
#define PROMPT_PASS_LEN		64

/* struct used to prompt for a secret passphrase
 * from a console with file descriptor fd
 */
typedef struct {
    char secret[PROMPT_PASS_LEN+1];
    bool prompt;
    int fd;
} prompt_pass_t;

/* no time defined in time_t */
#define UNDEFINED_TIME	0

/* size of timetoa string buffer */
#define TIMETOA_BUF	30

/* filter eliminating the directory entries '.' and '..' */
typedef struct dirent dirent_t;
extern int file_select(const dirent_t *entry);

/* cleanly exit Pluto */

extern void exit_pluto(int /*status*/) NEVER_RETURNS;


/* zero all bytes */
#define zero(x) memset((x), '\0', sizeof(*(x)))

/* are all bytes 0? */
extern bool all_zero(const unsigned char *m, size_t len);

/* pad_up(n, m) is the amount to add to n to make it a multiple of m */
#define pad_up(n, m) (((m) - 1) - (((n) + (m) - 1) % (m)))

#endif /* _DEFS_H */

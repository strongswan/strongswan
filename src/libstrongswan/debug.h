/**
 * @file log.h
 *
 * @brief Logging functions for the library.
 *
 */

/*
 * Copyright (C) 2006 Martin Willi
 * Hochschule fuer Technik Rapperswil
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

#ifndef DEBUG_H_
#define DEBUG_H_

#ifndef DEBUG_LEVEL
# define DEBUG_LEVEL 4
#endif /* DEBUG_LEVEL */

/** debug macros, they call the dbg function hook */
#if DEBUG_LEVEL >= 1
# define DBG1(fmt, ...) dbg(1, fmt, ##__VA_ARGS__)
#endif /* DEBUG_LEVEL */
#if DEBUG_LEVEL >= 2
# define DBG2(fmt, ...) dbg(2, fmt, ##__VA_ARGS__)
#endif /* DEBUG_LEVEL */
#if DEBUG_LEVEL >= 3
# define DBG3(fmt, ...) dbg(3, fmt, ##__VA_ARGS__)
#endif /* DEBUG_LEVEL */
#if DEBUG_LEVEL >= 4
# define DBG4(fmt, ...) dbg(4, fmt, ##__VA_ARGS__)
#endif /* DEBUG_LEVEL */

#ifndef DBG1
# define DBG1(...) {}
#endif
#ifndef DBG2
# define DBG2(...) {}
#endif
#ifndef DBG3
# define DBG3(...) {}
#endif
#ifndef DBG4
# define DBG4(...) {}
#endif

/** dbg function hook, uses stderr logger by default */
extern void (*dbg) (int level, char *fmt, ...);

#endif /* DEBUG_H_ */

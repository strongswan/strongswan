/*
 * Copyright (C) 2009 Martin Willi
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

#define _GNU_SOURCE

#include "integrity_checker.h"

#include <dlfcn.h>
#include <link.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <debug.h>
#include <library.h>

typedef struct private_integrity_checker_t private_integrity_checker_t;

/**
 * Private data of an integrity_checker_t object.
 */
struct private_integrity_checker_t {
	
	/**
	 * Public integrity_checker_t interface.
	 */
	integrity_checker_t public;
	
	/**
	 * dlopen handle to checksum library
	 */
	void *handle;
	
	/**
	 * checksum array
	 */
	integrity_checksum_t *checksums;
	
	/**
	 * number of checksums in array
	 */
	int checksum_count;
};

/**
 * Implementation of integrity_checker_t.build_file
 */
static u_int32_t build_file(private_integrity_checker_t *this, char *file)
{
	u_int32_t checksum;
	chunk_t contents;
	struct stat sb;
	void *addr;
	int fd;
	
	fd = open(file, O_RDONLY);
	if (fd == -1)
	{
		DBG1("opening '%s' failed: %s", file, strerror(errno));
		return 0;
	}
	
	if (fstat(fd, &sb) == -1)
	{
		DBG1("getting file size of '%s' failed: %s", file, strerror(errno));
		close(fd);
		return 0;
	}
	
	addr = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED)
	{
		DBG1("mapping '%s' failed: %s", file, strerror(errno));
		close(fd);
		return 0;
	}
	
	contents = chunk_create(addr, sb.st_size);
	checksum = chunk_hash(contents);
	
	munmap(addr, sb.st_size);
	close(fd);
	
	return checksum;
}

/**
 * dl_iterate_phdr callback function
 */
static int callback(struct dl_phdr_info *dlpi, size_t size, Dl_info *dli)
{
	if (dli->dli_fbase == (void*)dlpi->dlpi_addr)
	{
		int i;
		
		for (i = 0; i < dlpi->dlpi_phnum; i++)
		{
			const Elf32_Phdr *sgmt = &dlpi->dlpi_phdr[i];
			
			/* we are interested in the executable LOAD segment */
			if (sgmt->p_type == PT_LOAD &&
				(sgmt->p_flags & (PF_X | PF_R)))
			{
				/* safe begin of segment in dli_fbase */
				dli->dli_fbase = (void*)sgmt->p_vaddr + dlpi->dlpi_addr;
				/* safe end of segment in dli_saddr */
				dli->dli_saddr = dli->dli_fbase + sgmt->p_memsz;
				return 1;
			}
		}
	}
	return 0;
}

/**
 * Implementation of integrity_checker_t.build_segment
 */
static u_int32_t build_segment(private_integrity_checker_t *this, void *sym)
{
	chunk_t segment;
	Dl_info dli;
	
	if (dladdr(sym, &dli) == 0)
	{
		DBG1("unable to locate symbol: %s", strerror(errno));
		return 0;
	}
	/* we reuse the Dl_info struct as in/out parameter */
	if (!dl_iterate_phdr((void*)callback, &dli))
	{
		DBG1("executable section not found");
		return 0;
	}
	
	segment = chunk_create(dli.dli_fbase, dli.dli_saddr - dli.dli_fbase);
	return chunk_hash(segment);
}

/**
 * Find a checksum by its name
 */
static integrity_checksum_t *find_checksum(private_integrity_checker_t *this,
										   char *name)
{
	int i;
	
	for (i = 0; i < this->checksum_count; i++)
	{
		if (streq(this->checksums[i].name, name))
		{
			return &this->checksums[i];
		}
	}
	DBG1("no checksum found for %s", name);
	return NULL;
}

/**
 * Implementation of integrity_checker_t.check_file
 */
static bool check_file(private_integrity_checker_t *this,
					   char *name, char *file)
{
	integrity_checksum_t *cs;
	u_int32_t sum;
	
	cs = find_checksum(this, name);
	if (!cs)
	{
		DBG1("file checksum of %s is %08x", name, build_file(this, file));
		return FALSE;
	}
	sum = build_file(this, file);
	if (!sum || cs->file != sum)
	{
		DBG1("file checksum %s of '%s' invalid (got %08x, expected %08x)", 
			 name, file, sum, cs->file);
		return FALSE;
	}
	DBG1("file checksum %s of '%s' tested successfully", name, file);
	return TRUE;
}

/**
 * Implementation of integrity_checker_t.check_segment
 */
static bool check_segment(private_integrity_checker_t *this,
						  char *name, void *sym)
{
	integrity_checksum_t *cs;
	u_int32_t sum;
	
	cs = find_checksum(this, name);
	if (!cs)
	{
		DBG1("segment checksum of %s is %08x", name, build_segment(this, sym));
		return FALSE;
	}
	sum = build_segment(this, sym);
	if (!sum || cs->segment != sum)
	{
		DBG1("segment checksum %s invalid (got %08x, expected %08x)",
			 name, sum, cs->segment);
		return FALSE;
	}
	DBG1("segment checksum %s tested successfully", name);
	return TRUE;
}

/**
 * Implementation of integrity_checker_t.destroy.
 */
static void destroy(private_integrity_checker_t *this)
{
	if (this->handle)
	{
		dlclose(this->handle);
	}
	free(this);
}

/**
 * See header
 */
integrity_checker_t *integrity_checker_create(char *checksum_library)
{
	private_integrity_checker_t *this = malloc_thing(private_integrity_checker_t);
	
	this->public.check_file = (bool(*)(integrity_checker_t*, char *name, char *file))check_file;
	this->public.build_file = (u_int32_t(*)(integrity_checker_t*, char *file))build_file;
	this->public.check_segment = (bool(*)(integrity_checker_t*, char *name, void *sym))check_segment;
	this->public.build_segment = (u_int32_t(*)(integrity_checker_t*, void *sym))build_segment;
	this->public.destroy = (void(*)(integrity_checker_t*))destroy;
	
	this->checksum_count = 0;
	this->handle = NULL;
	if (checksum_library)
	{
		this->handle = dlopen(checksum_library, RTLD_LAZY);
		if (this->handle)
		{
			int *checksum_count;
		
			this->checksums = dlsym(this->handle, "checksums");
			checksum_count = dlsym(this->handle, "checksum_count");
			if (this->checksums && checksum_count)
			{
				this->checksum_count = *checksum_count;
			}
			else
			{
				DBG1("checksum library '%s' invalid", checksum_library);
			}
		}
		else
		{
			DBG1("loading checksum library '%s' failed", checksum_library);
		}
	}
	return &this->public;
}


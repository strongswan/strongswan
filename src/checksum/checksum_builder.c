/*
 * Copyright (C) 2009 Martin Willi
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

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>

#include <library.h>

/* we need to fake some charon symbols to dlopen() its plugins */
void *charon, *eap_type_names, *auth_class_names, *protocol_id_names,
*action_names, *ipsec_mode_names, *ike_sa_state_names, *child_sa_state_names,
*policy_dir_names, *ipcomp_transform_names, *debug_names, *controller_cb_empty;

int main(int argc, char* argv[])
{
	int i;
	integrity_checker_t *integrity;

	/* avoid confusing leak reports in build process */
	setenv("LEAK_DETECTIVE_DISABLE", "1", 0);
	library_init(NULL);
	atexit(library_deinit);

	integrity = integrity_checker_create(NULL);

	printf("/**\n");
	printf(" * checksums of files and loaded code segments.\n");
	printf(" * created by %s\n", argv[0]);
	printf(" */\n");
	printf("\n");
	printf("#include <library.h>\n");
	printf("\n");
	printf("integrity_checksum_t checksums[] = {\n");
	fprintf(stderr, "integrity test data:\n");
	fprintf(stderr, "module name,       file size / checksum   segment size / checksum\n");
	for (i = 1; i < argc; i++)
	{
		char *name, *path, *sname = NULL;
		void *handle, *symbol;
		u_int32_t fsum, ssum;
		size_t fsize = 0;
		size_t ssize = 0;

		path = argv[i];

		if ((name = strstr(path, "libstrongswan-")))
		{
			name = strdup(name + strlen("libstrongswan-"));
			if (asprintf(&sname, "%.*s_plugin_create", strlen(name) - 3,
						 name) < 0)
			{
				fprintf(stderr, "failed to format plugin constructor "
						"for '%s', ignored", path);
				free(name);
				continue;
			}
			translate(sname, "-", "_");
			name[strlen(name) - 3] = '"';
			name[strlen(name) - 2] = ',';
			name[strlen(name) - 1] = '\0';
		}
		else if (strstr(path, "libstrongswan.so"))
		{
			name = strdup("libstrongswan\",");
			sname = strdup("library_init");
		}
		else if (strstr(path, "pool"))
		{
			name = strdup("pool\",");
		}
		else if (strstr(path, "charon"))
		{
			name = strdup("charon\",");
		}
		else if (strstr(path, "pluto"))
		{
			name = strdup("pluto\",");
		}
		else if (strstr(path, "openac"))
		{
			name = strdup("openac\",");
		}
		else if (strstr(path, "scepclient"))
		{
			name = strdup("scepclient\",");
		}
		else if (strstr(path, "pki"))
		{
			name = strdup("pki\",");
		}
		else
		{
			fprintf(stderr, "don't know how to handle '%s', ignored", path);
			continue;
		}

		fsum = integrity->build_file(integrity, path, &fsize);
		ssum = 0;
		if (sname)
		{
			handle = dlopen(path, RTLD_LAZY);
			if (handle)
			{
				symbol = dlsym(handle, sname);
				if (symbol)
				{
					ssum = integrity->build_segment(integrity, symbol, &ssize);
				}
				else
				{
					fprintf(stderr, "symbol lookup failed: %s\n", dlerror());
				}
				dlclose(handle);
			}
			else
			{
				fprintf(stderr, "dlopen failed: %s\n", dlerror());
			}
		}
		printf("\t{\"%-20s%7u, 0x%08x, %6u, 0x%08x},\n",
			   name, fsize, fsum, ssize, ssum);
		fprintf(stderr, "\"%-20s%7u / 0x%08x       %6u / 0x%08x\n",
				name, fsize, fsum, ssize, ssum);
		free(sname);
		free(name);
	}
	printf("};\n");
	printf("\n");
	printf("int checksum_count = countof(checksums);\n");
	printf("\n");
	integrity->destroy(integrity);

	exit(0);
}


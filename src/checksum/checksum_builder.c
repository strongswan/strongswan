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

#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>

#include <library.h>

/* we need to fake some charon symbols to dlopen() its plugins */
void *eap_type_names, *auth_class_names, *charon, *protocol_id_names, 
*action_names, *ipsec_mode_names, *ike_sa_state_names, *child_sa_state_names,
*proposal_create_default, *peer_cfg_create, *ike_cfg_create, *child_cfg_create,
*traffic_selector_create_dynamic, *callback_job_create, *delete_ike_sa_job_create,
*eap_type_from_string, *auth_cfg_create, *proposal_create_from_string,
*traffic_selector_create_from_subnet, *traffic_selector_create_from_bytes,
*eap_payload_create_data, *ike_sa_create, *child_sa_create, *policy_dir_names,
*controller_cb_empty, *proposal_create, *ipcomp_transform_names,
*traffic_selector_create_from_string, *update_sa_job_create, *ike_sa_id_create,
*rekey_child_sa_job_create, *roam_job_create, *migrate_job_create,
*acquire_job_create, *delete_child_sa_job_create, *debug_names;

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
	for (i = 1; i < argc; i++)
	{
		char *name, *path, *sname;
		void *handle, *symbol;
		u_int32_t fsum, ssum;
		
		path = argv[i];
		
		if ((name = strstr(path, "libstrongswan-")))
		{
			name = strdup(name + strlen("libstrongswan-"));
			name[strlen(name) - 3] = '"';
			name[strlen(name) - 2] = ',';
			name[strlen(name) - 1] = '\0';
			sname = "plugin_create";
		}
		else if (strstr(path, "libstrongswan.so"))
		{
			name = strdup("libstrongswan\",");
			sname = "library_init";
		}
		else
		{
			fprintf(stderr, "don't know how to handle '%s', ignored", path);
			continue;
		}
		
		fsum = integrity->build_file(integrity, path);
		ssum = 0;
		handle = dlopen(path, RTLD_LAZY);
		if (handle)
		{
			symbol = dlsym(handle, sname);
			if (symbol)
			{
				ssum = integrity->build_segment(integrity, symbol);
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
		
		printf("\t{\"%-20s0x%08x, 0x%08x},\n", name, fsum, ssum);
		free(name);
	}
	printf("};\n");
	printf("\n");
	printf("int checksum_count = countof(checksums);\n");
	printf("\n");
	integrity->destroy(integrity);
	
	exit(0);
}


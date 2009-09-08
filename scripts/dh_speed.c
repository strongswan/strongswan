
#include <stdio.h>
#include <time.h>
#include <library.h>
#include <debug.h>
#include <crypto/diffie_hellman.h>

static void usage()
{
	printf("usage: dh_speed plugins rounds group1 [group2 [...]]\n");
	exit(1);
}

struct {
	char *name;
	diffie_hellman_group_t group;
} groups[] = {
	{"modp768",		MODP_768_BIT},
	{"modp1024",	MODP_1024_BIT},
	{"modp1536",	MODP_1536_BIT},
	{"modp2048",	MODP_2048_BIT},
	{"modp3072",	MODP_3072_BIT},
	{"modp4096",	MODP_4096_BIT},
	{"modp6144",	MODP_6144_BIT},
	{"modp8192",	MODP_8192_BIT},
	{"ecp256",		ECP_256_BIT},
	{"ecp384",		ECP_384_BIT},
	{"ecp521",		ECP_521_BIT},
	{"ecp192",		ECP_192_BIT},
	{"ecp224",		ECP_224_BIT},
};

static void start_timing(struct timespec *start)
{
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, start);
}

static double end_timing(struct timespec *start)
{
	struct timespec end;

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
	return (end.tv_nsec - start->tv_nsec) / 1000000000.0 +
			(end.tv_sec - start->tv_sec) * 1.0;
}

static void run_test(diffie_hellman_group_t group, int rounds)
{
	diffie_hellman_t *l[rounds], *r;
	chunk_t chunk;
	struct timespec timing;
	int round;

	r = lib->crypto->create_dh(lib->crypto, group);
	if (!r)
	{
		printf("skipping %N, not supported\n",
				diffie_hellman_group_names, group);
		return;
	}

	printf("%N:\t",
			diffie_hellman_group_names, group);

	start_timing(&timing);
	for (round = 0; round < rounds; round++)
	{
		l[round] = lib->crypto->create_dh(lib->crypto, group);
	}
	printf("A = g^a/s: %8.1f", rounds / end_timing(&timing));

	for (round = 0; round < rounds; round++)
	{
		l[round]->get_my_public_value(l[round], &chunk);
		r->set_other_public_value(r, chunk);
		chunk_free(&chunk);
	}

	r->get_my_public_value(r, &chunk);
	start_timing(&timing);
	for (round = 0; round < rounds; round++)
	{
		l[round]->set_other_public_value(l[round], chunk);
	}
	printf(" | S = B^a/s: %8.1f\n", rounds / end_timing(&timing));
	chunk_free(&chunk);

	for (round = 0; round < rounds; round++)
	{
		l[round]->destroy(l[round]);
	}
	r->destroy(r);
}

int main(int argc, char *argv[])
{
	int rounds, i, j;

	if (argc < 4)
	{
		usage();
	}

	library_init(STRONGSWAN_CONF);
	lib->plugins->load(lib->plugins, NULL, argv[1]);
	atexit(library_deinit);

	rounds = atoi(argv[2]);

	for (i = 3; i < argc; i++)
	{
		bool found = FALSE;

		for (j = 0; j < countof(groups); j++)
		{
			if (streq(groups[j].name, argv[i]))
			{
				run_test(groups[j].group, rounds);
				found = TRUE;
			}
		}
		if (!found)
		{
			printf("group %s not found\n", argv[i]);
		}
	}
	return 0;
}



#include <stdio.h>
#include <time.h>
#include <library.h>
#include <debug.h>
#include <credentials/keys/private_key.h>

void start_timing(struct timespec *start)
{
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, start);
}

double end_timing(struct timespec *start)
{
	struct timespec end;

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
	return (end.tv_nsec - start->tv_nsec) / 1000000000.0 +
			(end.tv_sec - start->tv_sec) * 1.0;
}

static void usage()
{
	printf("usage: pubkey_speed plugins rsa|ecdsa rounds\n");
	exit(1);
}

static char data_buf[] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07};

int main(int argc, char *argv[])
{
	private_key_t *private;
	public_key_t *public;
	struct timespec timing;
	int round, rounds, read;
	char buf[8096], *pos = buf;
	key_type_t type = KEY_ANY;
	signature_scheme_t scheme = SIGN_UNKNOWN;
	chunk_t keydata, *sigs, data = chunk_from_buf(data_buf);

	if (argc < 4)
	{
		usage();
	}

	rounds = atoi(argv[3]);

	if (streq(argv[2], "rsa"))
	{
		type = KEY_RSA;
		scheme = SIGN_RSA_EMSA_PKCS1_SHA1;
	}
	else if (streq(argv[2], "ecdsa"))
	{
		type = KEY_ECDSA;
	}
	else
	{
		usage();
	}

	library_init(NULL);
	lib->plugins->load(lib->plugins, NULL, argv[1]);
	atexit(library_deinit);

	keydata = chunk_create(buf, 0);
	while ((read = fread(pos, 1, sizeof(buf) - (pos - buf), stdin)))
	{
		pos += read;
		keydata.len += read;
	}

	private = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, type,
								 BUILD_BLOB_PEM, keydata, BUILD_END);
	if (!private)
	{
		printf("parsing private key failed.\n");
		exit(1);
	}
	if (type == KEY_ECDSA)
	{
		switch (private->get_keysize(private))
		{
			case 32:
				scheme = SIGN_ECDSA_256;
				break;
			case 48:
				scheme = SIGN_ECDSA_384;
				break;
			case 66:
				scheme = SIGN_ECDSA_521;
				break;
			default:
				printf("%d bit ECDSA private key size not supported",
						private->get_keysize(private) * 8);
				exit(1);
		}
	}

	printf("%4d bit %N: ", private->get_keysize(private)*8,
		key_type_names, type);

	sigs = malloc(sizeof(chunk_t) * rounds);

	start_timing(&timing);
	for (round = 0; round < rounds; round++)
	{
		if (!private->sign(private, scheme, data, &sigs[round]))
		{
			printf("creating signature failed\n");
			exit(1);
		}
	};
	printf("sign()/s: %8.1f   ", rounds / end_timing(&timing));

	public = private->get_public_key(private);
	if (!public)
	{
		printf("extracting public key failed\n");
		exit(1);
	}
	start_timing(&timing);
	for (round = 0; round < rounds; round++)
	{
		if (!public->verify(public, scheme, data, sigs[round]))
		{
			printf("signature verification failed\n");
			exit(1);
		}
	}
	printf("verify()/s: %8.1f\n", rounds / end_timing(&timing));
	public->destroy(public);
	private->destroy(private);

	for (round = 0; round < rounds; round++)
	{
		free(sigs[round].ptr);
	}
	free(sigs);
	return 0;
}


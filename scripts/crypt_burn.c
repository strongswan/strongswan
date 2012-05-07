
#include <stdio.h>
#include <library.h>
#include <crypto/proposal/proposal_keywords.h>

int main(int argc, char *argv[])
{
	const proposal_token_t *token;
	aead_t *aead;
	crypter_t *crypter;
	char buffer[1024], assoc[8], iv[32];
	size_t bs;
	int i = 0, limit = 0;


	library_init(NULL);
	lib->plugins->load(lib->plugins, NULL, PLUGINS);
	atexit(library_deinit);

	printf("loaded: %s\n", PLUGINS);

	memset(buffer, 0x12, sizeof(buffer));
	memset(assoc, 0x34, sizeof(assoc));
	memset(iv, 0x56, sizeof(iv));

	if (argc < 2)
	{
		fprintf(stderr, "usage: %s <algorithm>!\n", argv[0]);
		return 1;
	}
	if (argc > 2)
	{
		limit = atoi(argv[2]);
	}

	token = proposal_get_token(argv[1], strlen(argv[1]));
	if (!token)
	{
		fprintf(stderr, "algorithm '%s' unknown!\n", argv[1]);
		return 1;
	}
	if (token->type != ENCRYPTION_ALGORITHM)
	{
		fprintf(stderr, "'%s' is not an encryption/aead algorithm!\n", argv[1]);
		return 1;
	}

	if (encryption_algorithm_is_aead(token->algorithm))
	{
		aead = lib->crypto->create_aead(lib->crypto,
										token->algorithm, token->keysize / 8);
		if (!aead)
		{
			fprintf(stderr, "aead '%s' not supported!\n", argv[1]);
			return 1;
		}
		while (TRUE)
		{
			aead->encrypt(aead,
				chunk_create(buffer, sizeof(buffer) - aead->get_icv_size(aead)),
				chunk_from_thing(assoc),
				chunk_create(iv, aead->get_iv_size(aead)), NULL);
			if (!aead->decrypt(aead, chunk_create(buffer, sizeof(buffer)),
				chunk_from_thing(assoc),
				chunk_create(iv, aead->get_iv_size(aead)), NULL))
			{
				fprintf(stderr, "aead integrity check failed!\n");
				return 1;
			}
			if (limit && ++i == limit)
			{
				break;
			}
		}
	}
	else
	{
		crypter = lib->crypto->create_crypter(lib->crypto,
										token->algorithm, token->keysize / 8);
		if (!crypter)
		{
			fprintf(stderr, "crypter '%s' not supported!\n", argv[1]);
			return 1;
		}
		bs = crypter->get_block_size(crypter);

		while (i--)
		{
			crypter->encrypt(crypter,
				chunk_create(buffer, sizeof(buffer) / bs * bs),
				chunk_create(iv, crypter->get_iv_size(crypter)), NULL);
			crypter->decrypt(crypter,
				chunk_create(buffer, sizeof(buffer) / bs * bs),
				chunk_create(iv, crypter->get_iv_size(crypter)), NULL);
			if (limit && ++i == limit)
			{
				break;
			}
		}
	}
	return 0;
}

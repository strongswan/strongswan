
#include <stdio.h>
#include <library.h>
#include <debug.h>

/**
 * print the keyids of a private or public key in sql format
 */
int main(int argc, char *argv[])
{
	public_key_t *public;
	private_key_t *private;
	identification_t *keyid;
	chunk_t chunk;
	char buf[8096];
	int read, n;
	
	library_init(NULL);
	lib->plugins->load(lib->plugins, IPSEC_PLUGINDIR, "gmp pubkey sha1");
	atexit(library_deinit);

	read = fread(buf, 1, sizeof(buf), stdin);
	if (read <= 0)
	{
		fprintf(stderr, "reading key failed.\n");
		return -1;
	}
	
	chunk = chunk_create(buf, read);
	
	private = lib->creds->create(lib->creds, CRED_PRIVATE_KEY, KEY_RSA,
								 BUILD_BLOB_ASN1_DER, chunk_clone(chunk),
								 BUILD_END);
	if (private)
	{
		keyid = private->get_id(private, ID_PUBKEY_INFO_SHA1);
		chunk = keyid->get_encoding(keyid);

		printf("%d, X'", ID_PUBKEY_INFO_SHA1);
		for (n = 0; n < chunk.len; n++)
		{
			printf("%.2x", chunk.ptr[n]);
		}
		printf("'\n");
		private->destroy(private);
		return 0;
	}
	
	public = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_ANY,
								BUILD_BLOB_ASN1_DER, chunk_clone(chunk),
								BUILD_END);
	if (!public)
	{
		public = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_RSA,
									BUILD_BLOB_ASN1_DER, chunk_clone(chunk),
									BUILD_END);
	}
	if (public)
	{
		keyid = public->get_id(public, ID_PUBKEY_INFO_SHA1);
		chunk = keyid->get_encoding(keyid);

		printf("%d, X'", ID_PUBKEY_INFO_SHA1);
		for (n = 0; n < chunk.len; n++)
		{
			printf("%.2x", chunk.ptr[n]);
		}
		printf("'\n");
		public->destroy(public);
		return 0;
	}
	
	fprintf(stderr, "unable to parse input key.\n");
	return -1;
}


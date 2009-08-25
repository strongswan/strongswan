
#include <stdio.h>
#include <library.h>
#include <debug.h>
#include <credentials/keys/private_key.h>
#include <credentials/keys/public_key.h>

/**
 * print the keyids of a private or public key
 */
int main(int argc, char *argv[])
{
	public_key_t *public;
	private_key_t *private;
	chunk_t chunk;
	char buf[8096];
	int read;
	
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
		printf("parsed %d bits %N private key.\n",
			   private->get_keysize(private)*8,
			   key_type_names, private->get_type(private));
		if (private->get_fingerprint(private, KEY_ID_PUBKEY_INFO_SHA1, &chunk))
		{
			printf("subjectPublicKeyInfo keyid: %#B\n", &chunk);
		}
		if (private->get_fingerprint(private, KEY_ID_PUBKEY_SHA1, &chunk))
		{
			printf("subjectPublicKey keyid:     %#B\n", &chunk);
		}
		if (private->get_fingerprint(private, KEY_ID_PGPV3, &chunk))
		{
			printf("PGP verison 3 keyid:        %#B\n", &chunk);
		}
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
		printf("parsed %d bits %N public key.\n",
			   public->get_keysize(public)*8,
			   key_type_names, public->get_type(public));
		if (public->get_fingerprint(public, KEY_ID_PUBKEY_INFO_SHA1, &chunk))
		{
			printf("subjectPublicKeyInfo keyid: %#B\n", &chunk);
		}
		if (public->get_fingerprint(public, KEY_ID_PUBKEY_SHA1, &chunk))
		{
			printf("subjectPublicKey keyid:     %#B\n", &chunk);
		}
		if (public->get_fingerprint(public, KEY_ID_PGPV3, &chunk))
		{
			printf("PGP verison 3 keyid:        %#B\n", &chunk);
		}
		public->destroy(public);
		return 0;
	}
	
	fprintf(stderr, "unable to parse input key.\n");
	return -1;
}


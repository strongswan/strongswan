/**
 * @file aes_crypter.c
 * 
 * @brief Implementation of aes_crypter_t
 * 
 */
 
#include "aes_crypter.h"

#include <utils/allocator.h>


typedef struct private_aes_crypter_t private_aes_crypter_t;

/**
 * @brief Class implementing the AES symmetric encryption algorithm.
 * 
 * @ingroup crypters
 */
struct private_aes_crypter_t {
	
	/**
	 * Public part of this class
	 */
	aes_crypter_t public;
	
};

/**
 * Implementation of crypter_t.encrypt.
 */
static status_t encrypt (private_aes_crypter_t *this, chunk_t data, chunk_t *encrypted)
{
	return SUCCESS;
}

/**
 * Implementation of crypter_t.decrypt.
 */
static status_t decrypt (private_aes_crypter_t *this, chunk_t data, chunk_t *decrypted)
{
	return SUCCESS;
}

/**
 * Implementation of crypter_t.get_block_size.
 */
static size_t get_block_size (private_aes_crypter_t *this)
{
	return SUCCESS;
}

/**
 * Implementation of crypter_t.set_key.
 */
static status_t set_key (private_aes_crypter_t *this, chunk_t key)
{
	return SUCCESS;
}

/**
 * Implementation of crypter_t.destroy and aes_crypter_t.destroy.
 */
static status_t destroy (private_aes_crypter_t *this)
{
	return SUCCESS;
}


aes_crypter_t *aes_crypter_create()
{
	private_aes_crypter_t *this = allocator_alloc_thing(private_aes_crypter_t);
	if (this == NULL)
	{
		return NULL;	
	}

	/* functions of crypter_t interface */	
	this->public.crypter_interface.encrypt = (status_t (*) (crypter_t *, chunk_t , chunk_t *)) encrypt;
	this->public.crypter_interface.decrypt = (status_t (*) (crypter_t *, chunk_t , chunk_t *)) decrypt;
	this->public.crypter_interface.get_block_size = (size_t (*) (crypter_t *)) get_block_size;
	this->public.crypter_interface.set_key = (status_t (*) (crypter_t *,chunk_t)) set_key;
	this->public.crypter_interface.destroy = (status_t (*) (crypter_t *)) destroy;

	/* public functions */
	this->public.destroy = (status_t (*) (aes_crypter_t *)) destroy;
	
	
	return &(this->public);
}

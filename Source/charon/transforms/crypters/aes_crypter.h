/**
 * @file aes_crypter.h
 * 
 * @brief Interface of aes_crypter_t
 * 
 */


#ifndef _AES_CRYPTER_H_
#define _AES_CRYPTER_H_

#include <transforms/crypters/crypter.h>


typedef struct aes_crypter_t aes_crypter_t;

/**
 * @brief Class implementing the AES symmetric encryption algorithm.
 * 
 * @ingroup crypters
 */
struct aes_crypter_t {
	
	/**
	 * crypter_t interface.
	 */
	crypter_t crypter_interface;
	
	/**
	 * @brief Destroys a aes_crypter_t object.
	 *
	 * @param this 				crypter_t object to destroy
	 * @return 		
	 * 							- SUCCESS in any case
	 */
	status_t (*destroy) (aes_crypter_t *this);
};

/**
 * @brief Constructor to create aes_crypter_t objects.
 * 
 * @return
 * 								- aes_crypter_t if successfully
 * 								- NULL if out of ressources
 */
aes_crypter_t *aes_crypter_create();



#endif //_AES_CRYPTER_H_

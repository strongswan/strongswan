#ifndef DUMM_H
#define DUMM_H

#include <library.h>
#include <utils/linked_list.h>

#include "guest.h"

#define HOST_DIR "host"
#define MOUNT_DIR "mount"
#define RUN_DIR "run"


typedef struct dumm_t dumm_t;

/**
 * @brief dumm - Dynamic Uml Mesh Modeler
 *
 * Controls a group of UML guests and their networks.
 */
struct dumm_t {

	/**
	 * @brief Starts a new UML guest
	 *
	 * @param name		name of the guest
	 * @param kernel	kernel to boot
	 * @param master	mounted read only master filesystem
	 * @param mem		amount of memory for guest, in MB
	 * @return			guest if started, NULL if failed
	 */
	guest_t* (*start_guest) (dumm_t *this, char *name, char *kernel,
							 char *master, int mem);
	
	/**
	 * @brief Create an iterator over all guests.
	 *
	 * @return			iteraotor over guest_t's
	 */
	iterator_t* (*create_guest_iterator) (dumm_t *this);
	
	/**
	 * @brief stop all guests and destroy the modeler
	 */
	void (*destroy) (dumm_t *this);
};

dumm_t *dumm_create();

#endif /* DUMM_H */

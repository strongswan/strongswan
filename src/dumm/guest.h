#ifndef GUEST_H
#define GUEST_H

#include <library.h>
#include <utils/linked_list.h>

typedef struct guest_t guest_t;

struct guest_t {
	
	char* (*get_name) (guest_t *this);
	
	bool (*start) (guest_t *this);
	
	bool (*stop) (guest_t *this);
	
	void (*destroy) (guest_t *this);
};

guest_t *guest_create(char *name, char *kernel, char *master, int mem);


#endif /* GUEST_H */

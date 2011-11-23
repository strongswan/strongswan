
/**
 * @defgroup xauth_request xauth_request
 * @{ @ingroup tasks
 */

#ifndef XAUTH_REQUEST_H_
#define XAUTH_REQUEST_H_

typedef struct xauth_request_t xauth_request_t;

#include <library.h>
#include <sa/ike_sa.h>
#include <sa/tasks/task.h>

/**
 * Task of type XAUTH_REQUEST, gets the username and password from the ISAKMP_SA
 * initializer.
 */
struct xauth_request_t {

	/**
	 * Implements the task_t interface
	 */
	task_t task;
};

/**
 * Create a new xauth_request task.
 *
 * @param ike_sa		IKE_SA this task works for
 * @param initiator		TRUE for initiator
 * @return				ike_config task to handle by the task_manager
 */
xauth_request_t *xauth_request_create(ike_sa_t *ike_sa, bool initiator);

#endif /** XAUTH_REQUEST_H_ @}*/

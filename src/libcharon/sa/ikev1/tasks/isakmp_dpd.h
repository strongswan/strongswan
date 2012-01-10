#ifndef ISAKMP_DPD_H_
#define ISAPMP_DPD_H_

typedef struct isakmp_dpd_t isakmp_dpd_t;

#include <library.h>
#include <sa/ike_sa.h>
#include <sa/task.h>

/**
 * Task of type isakmp_dpd, detects dead peers.
 *
 *
 */
struct isakmp_dpd_t {

	/**
	 * Implements the task_t interface
	 */
	task_t task;

	/**
	 * Get the received dpd seqnr.
	 *
	 * @return				protocol ID
	 */
	u_int32_t (*get_dpd_seqnr) (isakmp_dpd_t *dpd_task);
};

/**
 * Create a new isakmp_dpd task.
 *
 * @param initiator		TRUE if task is the original initiator
 * @return				isakmp_dpd task to handle by the task_manager
 */
isakmp_dpd_t *isakmp_dpd_create(ike_sa_t *ike_sa, notify_payload_t *notify, u_int32_t seqnr);

#endif /** ISAKMP_DPD_H_ @}*/
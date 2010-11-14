/*
 * Copyright (C) 2010 Andreas Steffen
 * HSR Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/**
 * @defgroup imv_recommendations imv_recommendations
 * @{ @ingroup libcharon
 */

#ifndef IMV_RECOMMENDATIONS_H_
#define IMV_RECOMMENDATIONS_H_

#include <tnc/tncifimv.h>
#include <library.h>

typedef enum recommendation_policy_t recommendation_policy_t;

enum recommendation_policy_t {
	RECOMMENDATION_POLICY_NONE,
	RECOMMENDATION_POLICY_ANY,
	RECOMMENDATION_POLICY_ALL
};

extern enum_name_t *recommendation_policy_names;


typedef struct recommendations_t recommendations_t;

/**
 * Collection of all IMV action recommendations and evaluation results
 */
struct recommendations_t {

	/**
	 * Deliver an IMV action recommendation and IMV evaluation result to the TNCS
	 *
	 * @param imv_id			ID of the IMV providing the recommendation
	 * @param recommendation	action recommendation
	 * @param evaluation		evaluation result
	 */
	TNC_Result (*provide_recommendation)(recommendations_t *this,
										 TNC_IMVID imv_id,
										 TNC_IMV_Action_Recommendation rec,
										 TNC_IMV_Evaluation_Result eval);

	bool (*have_recommendation)(recommendations_t *this,
								TNC_IMV_Action_Recommendation *rec,
								TNC_IMV_Evaluation_Result *eval);

	/**
	 * Destroys an imv_t object.
	 */
	void (*destroy)(recommendations_t *this);
};

#endif /** IMV_RECOMMENDATIONS_H_ @}*/

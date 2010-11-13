/*
 * Copyright (C) 2010 Andreas Steffen, HSR Hochschule fuer Technik Rapperswil
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

#include <debug.h>
#include <utils/linked_list.h>
#include <threading/mutex.h>
#include <tnc/tncifimv_names.h>
#include <tnc/imv/imv_recommendations.h>

typedef struct private_tnc_imv_recommendations_t private_tnc_imv_recommendations_t;
typedef struct recommendation_entry_t recommendation_entry_t;

/**
 * Recommendation entry
 */
struct recommendation_entry_t {

	/**
	 * IMV ID
	 */
	TNC_IMVID id;

	/**
	 * Action Recommendation provided by IMV instance
	 */
  TNC_IMV_Action_Recommendation rec;

	/**
	 * Evaluation Result provided by IMV instance
	 */
  TNC_IMV_Evaluation_Result eval;
};

/**
 * Private data of a recommendations_t object.
 */
struct private_tnc_imv_recommendations_t {

	/**
	 * Public members of recommendations_t.
	 */
	recommendations_t public;

	/**
	 * list of recommendations and evaluations provided by IMVs 
	 */
	linked_list_t *recs;
};

METHOD(recommendations_t, provide_recommendation, TNC_Result,
	private_tnc_imv_recommendations_t* this, TNC_IMVID id,
											 TNC_IMV_Action_Recommendation rec,
											 TNC_IMV_Evaluation_Result eval)
{
	enumerator_t *enumerator;
	recommendation_entry_t *entry;
	bool found = FALSE;

	DBG2(DBG_TNC, "IMV %u provides recommendation '%N' and evaluation '%N'",
		 id, action_recommendation_names, rec, evaluation_result_names, eval);

	enumerator = this->recs->create_enumerator(this->recs);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (entry->id == id)
		{
			found = TRUE;
			entry->rec = rec;
			entry->eval = eval;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return found ? TNC_RESULT_SUCCESS : TNC_RESULT_FATAL;
}

METHOD(recommendations_t, have_recommendation, bool,
	private_tnc_imv_recommendations_t *this, TNC_IMV_Action_Recommendation *rec,
											 TNC_IMV_Evaluation_Result *eval)
{
	/* TODO */
	*rec = TNC_IMV_ACTION_RECOMMENDATION_ALLOW;
	*eval = TNC_IMV_EVALUATION_RESULT_COMPLIANT;
	return TRUE;
}

METHOD(recommendations_t, destroy, void,
	private_tnc_imv_recommendations_t *this)
{
	this->recs->destroy_function(this->recs, free);
	free(this);
}

/**
 * Described in header.
 */
recommendations_t* tnc_imv_recommendations_create(linked_list_t *imv_list)
{
	private_tnc_imv_recommendations_t *this;
	recommendation_entry_t *entry;
	enumerator_t *enumerator;
	TNC_IMVID id;

	INIT(this,
		.public = {
			.provide_recommendation = _provide_recommendation,
			.have_recommendation = _have_recommendation,
			.destroy = _destroy,
        },
		.recs = linked_list_create(),
	);

	enumerator = imv_list->create_enumerator(imv_list);
	while (enumerator->enumerate(enumerator, &id))
	{
		entry = malloc_thing(recommendation_entry_t);
		entry->id = id;
		entry->rec = TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION;
		entry->eval = TNC_IMV_EVALUATION_RESULT_DONT_KNOW;
		this->recs->insert_last(this->recs, entry);		
	}
	enumerator->destroy(enumerator);	

	return &this->public;
}

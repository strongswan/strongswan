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
#include <daemon.h>
#include <tnc/tncifimv_names.h>
#include <tnc/imv/imv.h>
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
	 * Received a recommendation message from this IMV?
	 */
	bool have_recommendation;

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

	/**
	 * Preferred language for remediation messages
	 */
	chunk_t preferred_language;
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
			entry->have_recommendation = TRUE;
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
	enumerator_t *enumerator;
	recommendation_entry_t *entry;
	recommendation_policy_t policy;
	TNC_IMV_Action_Recommendation final_rec;
	TNC_IMV_Evaluation_Result final_eval;
	bool first = TRUE, incomplete = FALSE;

	*rec = final_rec = TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION;
	*eval = final_eval = TNC_IMV_EVALUATION_RESULT_DONT_KNOW;

	if (this->recs->get_count(this->recs) == 0)
	{
		DBG1(DBG_TNC, "there are no IMVs to make a recommendation");
		return TRUE;
	}
	policy = charon->imvs->get_recommendation_policy(charon->imvs);

	enumerator = this->recs->create_enumerator(this->recs);
	while (enumerator->enumerate(enumerator, &entry))
	{
		if (!entry->have_recommendation)
		{
			incomplete = TRUE;
			break;
		}
		if (first)
		{
			final_rec = entry->rec;
			final_eval = entry->eval;
			first = FALSE;
			continue;
		}
		switch (policy)
		{
			case RECOMMENDATION_POLICY_DEFAULT:
				switch (entry->rec)
				{
					case TNC_IMV_ACTION_RECOMMENDATION_NO_ACCESS:
						final_rec = entry->rec;
						break;
					case TNC_IMV_ACTION_RECOMMENDATION_ISOLATE:
						if (final_rec != TNC_IMV_ACTION_RECOMMENDATION_NO_ACCESS)
						{
							final_rec = entry->rec;
						};
						break;
					case TNC_IMV_ACTION_RECOMMENDATION_ALLOW:
						if (final_rec == TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION)
						{
							final_rec = entry->rec;
						};
						break;
					case TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION:
						break;
				}
				switch (entry->eval)
				{
					case TNC_IMV_EVALUATION_RESULT_ERROR:
						final_eval = entry->eval;
						break;
					case TNC_IMV_EVALUATION_RESULT_NONCOMPLIANT_MAJOR:
						if (final_eval != TNC_IMV_EVALUATION_RESULT_ERROR)
						{
							final_eval = entry->eval;
						}
						break;
					case TNC_IMV_EVALUATION_RESULT_NONCOMPLIANT_MINOR:
						if (final_eval != TNC_IMV_EVALUATION_RESULT_ERROR &&
							final_eval != TNC_IMV_EVALUATION_RESULT_NONCOMPLIANT_MAJOR)
						{
							final_eval = entry->eval;
						}
						break;
					case TNC_IMV_EVALUATION_RESULT_COMPLIANT:
						if (final_eval == TNC_IMV_EVALUATION_RESULT_DONT_KNOW)
						{
							final_eval = entry->eval;
						}
						break;
					case TNC_IMV_EVALUATION_RESULT_DONT_KNOW:
						break;
				}
				break;

			case RECOMMENDATION_POLICY_ALL:
				if (entry->rec != final_rec)
				{
					final_rec = TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION;
				}
				if (entry->eval != final_eval)
				{
					final_eval = TNC_IMV_EVALUATION_RESULT_DONT_KNOW;
				}
				break;

			case RECOMMENDATION_POLICY_ANY:
				switch (entry->rec)
				{
					case TNC_IMV_ACTION_RECOMMENDATION_ALLOW:
						final_rec = entry->rec;
						break;
					case TNC_IMV_ACTION_RECOMMENDATION_ISOLATE:
						if (final_rec != TNC_IMV_ACTION_RECOMMENDATION_ALLOW)
						{
							final_rec = entry->rec;
						};
						break;
					case TNC_IMV_ACTION_RECOMMENDATION_NO_ACCESS:
						if (final_rec == TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION)
						{
							final_rec = entry->rec;
						};
						break;
					case TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION:
						break;
				}
				switch (entry->eval)
				{
					case TNC_IMV_EVALUATION_RESULT_COMPLIANT:
						final_eval = entry->eval;
						break;
					case TNC_IMV_EVALUATION_RESULT_NONCOMPLIANT_MINOR:
						if (final_eval != TNC_IMV_EVALUATION_RESULT_COMPLIANT)
						{
							final_eval = entry->eval;
						}
						break;
					case TNC_IMV_EVALUATION_RESULT_NONCOMPLIANT_MAJOR:
						if (final_eval != TNC_IMV_EVALUATION_RESULT_COMPLIANT &&
							final_eval != TNC_IMV_EVALUATION_RESULT_NONCOMPLIANT_MINOR)
						{
							final_eval = entry->eval;
						}
						break;
					case TNC_IMV_EVALUATION_RESULT_ERROR:
						if (final_eval == TNC_IMV_EVALUATION_RESULT_DONT_KNOW)
						{
							final_eval = entry->eval;
						}
						break;
					case TNC_IMV_EVALUATION_RESULT_DONT_KNOW:
						break;
				}
		}
	}
	enumerator->destroy(enumerator);

	if (incomplete)
	{
		return FALSE;
	}
	*rec = final_rec;
	*eval = final_eval;
	return TRUE;
}

METHOD(recommendations_t, get_preferred_language, chunk_t,
	private_tnc_imv_recommendations_t *this)
{
	return this->preferred_language;
}

METHOD(recommendations_t, set_preferred_language, void,
	private_tnc_imv_recommendations_t *this, chunk_t pref_lang)
{
	chunk_free(&this->preferred_language);
	this->preferred_language = chunk_clone(pref_lang);
}

METHOD(recommendations_t, destroy, void,
	private_tnc_imv_recommendations_t *this)
{
	this->recs->destroy_function(this->recs, free);
	free(this->preferred_language.ptr);
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
	imv_t *imv;

	INIT(this,
		.public = {
			.provide_recommendation = _provide_recommendation,
			.have_recommendation = _have_recommendation,
			.get_preferred_language = _get_preferred_language,
			.set_preferred_language = _set_preferred_language,
			.destroy = _destroy,
        },
		.recs = linked_list_create(),
	);

	enumerator = imv_list->create_enumerator(imv_list);
	while (enumerator->enumerate(enumerator, &imv))
	{
		entry = malloc_thing(recommendation_entry_t);
		entry->id = imv->get_id(imv);
		entry->have_recommendation = FALSE;
		entry->rec = TNC_IMV_ACTION_RECOMMENDATION_NO_RECOMMENDATION;
		entry->eval = TNC_IMV_EVALUATION_RESULT_DONT_KNOW;
		this->recs->insert_last(this->recs, entry);		
	}
	enumerator->destroy(enumerator);	

	return &this->public;
}

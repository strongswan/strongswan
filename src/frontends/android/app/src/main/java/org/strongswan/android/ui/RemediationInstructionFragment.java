/*
 * Copyright (C) 2013 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
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

package org.strongswan.android.ui;

import org.strongswan.android.R;
import org.strongswan.android.logic.imc.RemediationInstruction;

import android.app.ListFragment;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.TextView;

public class RemediationInstructionFragment extends ListFragment
{
	public static final String ARG_REMEDIATION_INSTRUCTION = "instruction";
	private RemediationInstruction mInstruction = null;
	private TextView mTitle;
	private TextView mDescription;
	private TextView mHeader;

	@Override
	public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState)
	{
		return inflater.inflate(R.layout.remediation_instruction, container, false);
	}

	@Override
	public void onActivityCreated(Bundle savedInstanceState)
	{
		super.onActivityCreated(savedInstanceState);

		if (savedInstanceState != null)
		{
			mInstruction = savedInstanceState.getParcelable(ARG_REMEDIATION_INSTRUCTION);
		}
		/* show dividers only between list items */
		getListView().setHeaderDividersEnabled(false);
		getListView().setFooterDividersEnabled(false);
		/* don't show loader while adapter is not set */
		setListShown(true);
		mTitle = (TextView)getView().findViewById(R.id.title);
		mDescription = (TextView)getView().findViewById(R.id.description);
		mHeader = (TextView)getView().findViewById(R.id.list_header);
	}

	@Override
	public void onSaveInstanceState(Bundle outState)
	{
		super.onSaveInstanceState(outState);
		outState.putParcelable(ARG_REMEDIATION_INSTRUCTION, mInstruction);
	}

	@Override
	public void onStart()
	{
		super.onStart();

		Bundle args = getArguments();
		if (args != null)
		{
			mInstruction = args.getParcelable(ARG_REMEDIATION_INSTRUCTION);
		}
		updateView(mInstruction);
	}

	public void updateView(RemediationInstruction instruction)
	{
		mInstruction = instruction;
		if (mInstruction != null)
		{
			mTitle.setText(mInstruction.getTitle());
			mDescription.setText(mInstruction.getDescription());
			if (mInstruction.getHeader() != null)
			{
				mHeader.setText(mInstruction.getHeader());
				setListAdapter(new ArrayAdapter<String>(getActivity(),
							   android.R.layout.simple_list_item_1, mInstruction.getItems()));
			}
			else
			{
				mHeader.setText("");
				setListAdapter(null);
			}
		}
		else
		{
			mTitle.setText("");
			mDescription.setText("");
			mHeader.setText("");
			setListAdapter(null);
		}
	}
}

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

import java.util.ArrayList;

import org.strongswan.android.R;
import org.strongswan.android.logic.imc.RemediationInstruction;
import org.strongswan.android.ui.RemediationInstructionsFragment.OnRemediationInstructionSelectedListener;

import android.app.Activity;
import android.os.Bundle;
import android.view.MenuItem;

public class RemediationInstructionsActivity extends Activity implements OnRemediationInstructionSelectedListener
{
	@Override
	protected void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);
		setContentView(R.layout.remediation_instructions);
		getActionBar().setDisplayHomeAsUpEnabled(true);

		if (savedInstanceState != null)
		{	/* only update if we're not restoring */
			return;
		}
		RemediationInstructionsFragment frag = (RemediationInstructionsFragment)getFragmentManager().findFragmentById(R.id.remediation_instructions_fragment);
		if (frag != null)
		{	/* two-pane layout, update fragment */
			Bundle extras = getIntent().getExtras();
			ArrayList<RemediationInstruction> list = extras.getParcelableArrayList(RemediationInstructionsFragment.EXTRA_REMEDIATION_INSTRUCTIONS);
			frag.updateView(list);
		}
		else
		{	/* one-pane layout, create fragment */
			frag = new RemediationInstructionsFragment();
			frag.setArguments(getIntent().getExtras());
			getFragmentManager().beginTransaction().add(R.id.fragment_container, frag).commit();
		}
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item)
	{
		switch (item.getItemId())
		{
			case android.R.id.home:
				/* one-pane layout, pop possible fragment from stack, finish otherwise */
				if (!getFragmentManager().popBackStackImmediate())
				{
					finish();
				}
				getActionBar().setTitle(getTitle());
				return true;
			default:
				return super.onOptionsItemSelected(item);
		}
	}

	@Override
	public void onRemediationInstructionSelected(RemediationInstruction instruction)
	{
		RemediationInstructionFragment frag = (RemediationInstructionFragment)getFragmentManager().findFragmentById(R.id.remediation_instruction_fragment);

		if (frag != null)
		{	/* two-pane layout, update directly */
			frag.updateView(instruction);
		}
		else
		{	/* one-pane layout, replace fragment */
			frag = new RemediationInstructionFragment();
			Bundle args = new Bundle();
			args.putParcelable(RemediationInstructionFragment.ARG_REMEDIATION_INSTRUCTION, instruction);
			frag.setArguments(args);

			getFragmentManager().beginTransaction().replace(R.id.fragment_container, frag).addToBackStack(null).commit();
			getActionBar().setTitle(instruction.getTitle());
		}
	}
}

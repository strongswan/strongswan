/*
 * Copyright (C) 2012 Tobias Brunner
 * Copyright (C) 2012 Giuliano Grassi
 * Copyright (C) 2012 Ralf Sager
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
import org.strongswan.android.data.VpnProfile;
import org.strongswan.android.data.VpnProfileDataSource;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.EditText;

public class VpnProfileDetailActivity extends Activity
{
	private VpnProfileDataSource mDataSource;
	private Long mId;
	private VpnProfile mProfile;
	private EditText mName;
	private EditText mGateway;
	private EditText mUsername;
	private EditText mPassword;

	@Override
	public void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);

		/* the title is set when we load the profile, if any */
		getActionBar().setDisplayHomeAsUpEnabled(true);

		mDataSource = new VpnProfileDataSource(this);
		mDataSource.open();

		setContentView(R.layout.profile_detail_view);

		mName = (EditText)findViewById(R.id.name);
		mPassword = (EditText)findViewById(R.id.password);
		mGateway = (EditText)findViewById(R.id.gateway);
		mUsername = (EditText)findViewById(R.id.username);

		mId = savedInstanceState == null ? null : savedInstanceState.getLong(VpnProfileDataSource.KEY_ID);
		if (mId == null)
		{
			Bundle extras = getIntent().getExtras();
			mId = extras == null ? null : extras.getLong(VpnProfileDataSource.KEY_ID);
		}

		loadProfileData();
	}

	@Override
	protected void onDestroy()
	{
		super.onDestroy();
		mDataSource.close();
	}

	@Override
	protected void onSaveInstanceState(Bundle outState)
	{
		super.onSaveInstanceState(outState);
		outState.putLong(VpnProfileDataSource.KEY_ID, mId);
	}

	/**
	 * Load an existing profile if we got an ID
	 */
	private void loadProfileData()
	{
		getActionBar().setTitle(R.string.add_profile);
		if (mId != null)
		{
			mProfile = mDataSource.getVpnProfile(mId);
			if (mProfile != null)
			{
				mName.setText(mProfile.getName());
				mGateway.setText(mProfile.getGateway());
				mUsername.setText(mProfile.getUsername());
				mPassword.setText(mProfile.getPassword());
				getActionBar().setTitle(mProfile.getName());
			}
			else
			{
				Log.e(VpnProfileDetailActivity.class.getSimpleName(),
					  "VPN profile with id " + mId + " not found");
				finish();
			}
		}
	}
}

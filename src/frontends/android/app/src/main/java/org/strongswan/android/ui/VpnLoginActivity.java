/*
 * Copyright (C) 2020 Tobias Brunner
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

package org.strongswan.android.ui;

import android.content.Intent;
import android.os.Bundle;

import org.strongswan.android.data.VpnProfileDataSource;
import org.strongswan.android.utils.Constants;

import androidx.appcompat.app.AppCompatActivity;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

public class VpnLoginActivity extends AppCompatActivity
{
	private static final String DIALOG_TAG = "Dialog";

	@Override
	public void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);

		LoginDialogFragment login = LoginDialogFragment.newInstance(getIntent().getExtras(), password -> {
			if (password != null)
			{
				Intent intent = new Intent(Constants.VPN_PASSWORD_ENTERED);
				intent.putExtra(VpnProfileDataSource.KEY_PASSWORD, password);
				LocalBroadcastManager.getInstance(this).sendBroadcast(intent);
			}
			finish();
		});
		login.show(getSupportFragmentManager(), DIALOG_TAG);
	}
}

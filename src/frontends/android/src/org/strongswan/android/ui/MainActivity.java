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
import org.strongswan.android.logic.CharonVpnService;
import org.strongswan.android.logic.TrustedCertificateManager;
import org.strongswan.android.ui.VpnProfileListFragment.OnVpnProfileSelectedListener;

import android.app.ActionBar;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.AlertDialog.Builder;
import android.app.Dialog;
import android.app.DialogFragment;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.VpnService;
import android.os.AsyncTask;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.Window;
import android.widget.EditText;

public class MainActivity extends Activity implements OnVpnProfileSelectedListener
{
	private static final int PREPARE_VPN_SERVICE = 0;
	private VpnProfile activeProfile;

	@Override
	public void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);
		requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);
		setContentView(R.layout.main);

		ActionBar bar = getActionBar();
		bar.setDisplayShowTitleEnabled(false);

		/* load CA certificates in a background task */
		new CertificateLoadTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, false);
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu)
	{
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item)
	{
		switch (item.getItemId())
		{
			case R.id.menu_reload_certs:
				new CertificateLoadTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, true);
				return true;
			case R.id.menu_show_log:
				Intent logIntent = new Intent(this, LogActivity.class);
				startActivity(logIntent);
				return true;
			default:
				return super.onOptionsItemSelected(item);
		}
	}

	/**
	 * Prepare the VpnService. If this succeeds the current VPN profile is
	 * started.
	 */
	protected void prepareVpnService()
	{
		Intent intent = VpnService.prepare(this);
		if (intent != null)
		{
			startActivityForResult(intent, PREPARE_VPN_SERVICE);
		}
		else
		{
			onActivityResult(PREPARE_VPN_SERVICE, RESULT_OK, null);
		}
	}

	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data)
	{
		switch (requestCode)
		{
			case PREPARE_VPN_SERVICE:
				if (resultCode == RESULT_OK && activeProfile != null)
				{
					Intent intent = new Intent(this, CharonVpnService.class);
					intent.putExtra(VpnProfileDataSource.KEY_ID, activeProfile.getId());
					/* submit the password as the profile might not store one */
					intent.putExtra(VpnProfileDataSource.KEY_PASSWORD, activeProfile.getPassword());
					this.startService(intent);
				}
				break;
			default:
				super.onActivityResult(requestCode, resultCode, data);
		}
	}

	@Override
	public void onVpnProfileSelected(VpnProfile profile)
	{
		activeProfile = profile;
		if (activeProfile.getPassword() == null)
		{
			new LoginDialog().show(getFragmentManager(), "LoginDialog");
		}
		else
		{
			prepareVpnService();
		}
	}

	/**
	 * Class that loads or reloads the cached CA certificates.
	 */
	private class CertificateLoadTask extends AsyncTask<Boolean, Void, TrustedCertificateManager>
	{
		@Override
		protected void onPreExecute()
		{
			setProgressBarIndeterminateVisibility(true);
		}
		@Override
		protected TrustedCertificateManager doInBackground(Boolean... params)
		{
			if (params.length > 0 && params[0])
			{	/* force a reload of the certificates */
				return TrustedCertificateManager.getInstance().reload();
			}
			return TrustedCertificateManager.getInstance().load();
		}
		@Override
		protected void onPostExecute(TrustedCertificateManager result)
		{
			setProgressBarIndeterminateVisibility(false);
		}
	}

	private class LoginDialog extends DialogFragment
	{
		@Override
		public Dialog onCreateDialog(Bundle savedInstanceState)
		{
			LayoutInflater inflater = (LayoutInflater)getSystemService(Context.LAYOUT_INFLATER_SERVICE);
			View view = inflater.inflate(R.layout.login_dialog, null);
			EditText username = (EditText)view.findViewById(R.id.username);
			username.setText(activeProfile.getUsername());
			final EditText password = (EditText)view.findViewById(R.id.password);

			Builder adb = new AlertDialog.Builder(MainActivity.this);
			adb.setView(view);
			adb.setTitle(getString(R.string.login_title));
			adb.setPositiveButton(R.string.login_confirm, new DialogInterface.OnClickListener() {
				@Override
				public void onClick(DialogInterface dialog, int whichButton)
				{
					/* let's work on a clone of the profile when updating the password */
					activeProfile = activeProfile.clone();
					activeProfile.setPassword(password.getText().toString().trim());
					prepareVpnService();
				}
			});
			adb.setNegativeButton(android.R.string.cancel, new DialogInterface.OnClickListener() {
				@Override
				public void onClick(DialogInterface dialog, int which)
				{
					dismiss();
				}
			});
			return adb.create();
		}
	}
}

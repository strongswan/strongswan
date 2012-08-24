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
import android.content.ActivityNotFoundException;
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
	public static final String CONTACT_EMAIL = "android@strongswan.org";
	private static final int PREPARE_VPN_SERVICE = 0;

	private Bundle mProfileInfo;

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
	 * @param profileInfo a bundle containing the information about the profile to be started
	 */
	protected void prepareVpnService(Bundle profileInfo)
	{
		Intent intent = VpnService.prepare(this);
		/* store profile info until the user grants us permission */
		mProfileInfo = profileInfo;
		if (intent != null)
		{
			try
			{
				startActivityForResult(intent, PREPARE_VPN_SERVICE);
			}
			catch (ActivityNotFoundException ex)
			{
				/* it seems some devices, even though they come with Android 4,
				 * don't have the VPN components built into the system image.
				 * com.android.vpndialogs/com.android.vpndialogs.ConfirmDialog
				 * will not be found then */
				new VpnNotSupportedError().show(getFragmentManager(), "ErrorDialog");
			}
		}
		else
		{	/* user already granted permission to use VpnService */
			onActivityResult(PREPARE_VPN_SERVICE, RESULT_OK, null);
		}
	}

	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data)
	{
		switch (requestCode)
		{
			case PREPARE_VPN_SERVICE:
				if (resultCode == RESULT_OK && mProfileInfo != null)
				{
					Intent intent = new Intent(this, CharonVpnService.class);
					intent.putExtras(mProfileInfo);
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
		Bundle profileInfo = new Bundle();
		profileInfo.putLong(VpnProfileDataSource.KEY_ID, profile.getId());
		profileInfo.putString(VpnProfileDataSource.KEY_USERNAME, profile.getUsername());
		if (profile.getPassword() == null)
		{
			LoginDialog login = new LoginDialog();
			login.setArguments(profileInfo);
			login.show(getFragmentManager(), "LoginDialog");
		}
		else
		{
			profileInfo.putString(VpnProfileDataSource.KEY_PASSWORD, profile.getPassword());
			prepareVpnService(profileInfo);
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

	/**
	 * Class that displays a login dialog and initiates the selected VPN
	 * profile if the user confirms the dialog.
	 */
	public static class LoginDialog extends DialogFragment
	{
		@Override
		public Dialog onCreateDialog(Bundle savedInstanceState)
		{
			final Bundle profileInfo = getArguments();
			LayoutInflater inflater = getActivity().getLayoutInflater();
			View view = inflater.inflate(R.layout.login_dialog, null);
			EditText username = (EditText)view.findViewById(R.id.username);
			username.setText(profileInfo.getString(VpnProfileDataSource.KEY_USERNAME));
			final EditText password = (EditText)view.findViewById(R.id.password);

			Builder adb = new AlertDialog.Builder(getActivity());
			adb.setView(view);
			adb.setTitle(getString(R.string.login_title));
			adb.setPositiveButton(R.string.login_confirm, new DialogInterface.OnClickListener() {
				@Override
				public void onClick(DialogInterface dialog, int whichButton)
				{
					MainActivity activity = (MainActivity)getActivity();
					profileInfo.putString(VpnProfileDataSource.KEY_PASSWORD, password.getText().toString().trim());
					activity.prepareVpnService(profileInfo);
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

	/**
	 * Class representing an error message which is displayed if VpnService is
	 * not supported on the current device.
	 */
	public static class VpnNotSupportedError extends DialogFragment
	{
		@Override
		public Dialog onCreateDialog(Bundle savedInstanceState)
		{
			return new AlertDialog.Builder(getActivity())
				.setTitle(R.string.vpn_not_supported_title)
				.setMessage(getString(R.string.vpn_not_supported))
				.setCancelable(false)
				.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
					@Override
					public void onClick(DialogInterface dialog, int id)
					{
						dialog.dismiss();
					}
				}).create();
		}
	}
}

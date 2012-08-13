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

import java.security.cert.X509Certificate;
import java.util.Hashtable;

import org.strongswan.android.R;
import org.strongswan.android.data.VpnProfile;
import org.strongswan.android.data.VpnProfileDataSource;
import org.strongswan.android.logic.TrustedCertificateManager;
import org.strongswan.android.ui.adapter.TrustedCertificateAdapter;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.Window;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.CompoundButton.OnCheckedChangeListener;
import android.widget.EditText;
import android.widget.Spinner;

public class VpnProfileDetailActivity extends Activity
{
	private VpnProfileDataSource mDataSource;
	private Long mId;
	private VpnProfile mProfile;
	private boolean mCertsLoaded;
	private String mCertAlias;
	private Spinner mCertSpinner;
	private TrustedCertificateAdapter.CertEntry mSelectedCert;
	private EditText mName;
	private EditText mGateway;
	private EditText mUsername;
	private EditText mPassword;
	private CheckBox mCheckAll;
	private CheckBox mCheckAuto;

	@Override
	public void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);
		requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);

		/* the title is set when we load the profile, if any */
		getActionBar().setDisplayHomeAsUpEnabled(true);

		mDataSource = new VpnProfileDataSource(this);
		mDataSource.open();

		setContentView(R.layout.profile_detail_view);

		mName = (EditText)findViewById(R.id.name);
		mPassword = (EditText)findViewById(R.id.password);
		mGateway = (EditText)findViewById(R.id.gateway);
		mUsername = (EditText)findViewById(R.id.username);

		mCheckAll = (CheckBox)findViewById(R.id.ca_show_all);
		mCheckAuto = (CheckBox)findViewById(R.id.ca_auto);
		mCertSpinner = (Spinner)findViewById(R.id.ca_spinner);

		mCheckAuto.setOnCheckedChangeListener(new OnCheckedChangeListener() {
			@Override
			public void onCheckedChanged(CompoundButton buttonView, boolean isChecked)
			{
				updateCertSpinner();
			}
		});

		mCheckAll.setOnCheckedChangeListener(new OnCheckedChangeListener() {
			@Override
			public void onCheckedChanged(CompoundButton buttonView, boolean isChecked)
			{
				Hashtable<String, X509Certificate> certs;
				certs = isChecked ? TrustedCertificateManager.getInstance().getAllCACertificates()
								  : TrustedCertificateManager.getInstance().getUserCACertificates();
				mCertSpinner.setAdapter(new TrustedCertificateAdapter(VpnProfileDetailActivity.this, certs));
				mSelectedCert = (TrustedCertificateAdapter.CertEntry)mCertSpinner.getSelectedItem();
			}
		});

		mCertSpinner.setOnItemSelectedListener(new OnItemSelectedListener() {
			@Override
			public void onItemSelected(AdapterView<?> parent, View view,
									   int pos, long id)
			{
				mSelectedCert = (TrustedCertificateAdapter.CertEntry)parent.getSelectedItem();
			}

			@Override
			public void onNothingSelected(AdapterView<?> arg0)
			{
				mSelectedCert = null;
			}
		});

		mId = savedInstanceState == null ? null : savedInstanceState.getLong(VpnProfileDataSource.KEY_ID);
		if (mId == null)
		{
			Bundle extras = getIntent().getExtras();
			mId = extras == null ? null : extras.getLong(VpnProfileDataSource.KEY_ID);
		}

		loadProfileData();

		new CertificateLoadTask().execute();
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

	@Override
	public boolean onCreateOptionsMenu(Menu menu)
	{
		MenuInflater inflater = getMenuInflater();
		inflater.inflate(R.menu.profile_edit, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item)
	{
		switch (item.getItemId())
		{
			case android.R.id.home:
			case R.id.menu_cancel:
				finish();
				return true;
			case R.id.menu_accept:
				saveProfile();
				return true;
			default:
				return super.onOptionsItemSelected(item);
		}
	}

	/**
	 * Show an alert in case the previously selected certificate is not found anymore
	 * or the user did not select a certificate in the spinner.
	 */
	private void showCertificateAlert()
	{
		AlertDialog.Builder adb = new AlertDialog.Builder(VpnProfileDetailActivity.this);
		adb.setTitle(R.string.alert_text_nocertfound_title);
		adb.setMessage(R.string.alert_text_nocertfound);
		adb.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
			@Override
			public void onClick(DialogInterface dialog, int id)
			{
				dialog.cancel();
			}
		});
		adb.show();
	}

	/**
	 * Asynchronously executed task which confirms that the certificates are loaded.
	 * They are loaded from the main Activity already but might not be ready yet, or
	 * unloaded again.
	 *
	 * Once loaded the CA certificate spinner and checkboxes are updated
	 * accordingly.
	 */
	private class CertificateLoadTask extends AsyncTask<Void, Void, TrustedCertificateManager>
	{
		@Override
		protected void onPreExecute()
		{
			setProgressBarIndeterminateVisibility(true);
		}

		@Override
		protected TrustedCertificateManager doInBackground(Void... params)
		{
			return TrustedCertificateManager.getInstance().load();
		}

		@Override
		protected void onPostExecute(TrustedCertificateManager result)
		{
			TrustedCertificateAdapter adapter;
			if (mCertAlias != null && mCertAlias.startsWith("system:"))
			{
				mCheckAll.setChecked(true);
				adapter = new TrustedCertificateAdapter(VpnProfileDetailActivity.this,
														result.getAllCACertificates());
			}
			else
			{
				mCheckAll.setChecked(false);
				adapter = new TrustedCertificateAdapter(VpnProfileDetailActivity.this,
														result.getUserCACertificates());
			}
			mCertSpinner.setAdapter(adapter);

			if (mCertAlias != null)
			{
				int position = adapter.getItemPosition(mCertAlias);
				if (position == -1)
				{	/* previously selected certificate is not here anymore */
					showCertificateAlert();
				}
				else
				{
					mCertSpinner.setSelection(position);
				}
			}

			mSelectedCert = (TrustedCertificateAdapter.CertEntry)mCertSpinner.getSelectedItem();

			setProgressBarIndeterminateVisibility(false);
			mCertsLoaded = true;
			updateCertSpinner();
		}
	}

	/**
	 * Update the CA certificate selection UI depending on whether the
	 * certificate should be automatically selected or not.
	 */
	private void updateCertSpinner()
	{
		if (!mCheckAuto.isChecked())
		{
			if (mCertsLoaded)
			{
				mCertSpinner.setEnabled(true);
				mCertSpinner.setVisibility(View.VISIBLE);
				mCheckAll.setEnabled(true);
				mCheckAll.setVisibility(View.VISIBLE);
			}
		}
		else
		{
			mCertSpinner.setEnabled(false);
			mCertSpinner.setVisibility(View.GONE);
			mCheckAll.setEnabled(false);
			mCheckAll.setVisibility(View.GONE);
		}
	}

	/**
	 * Save or update the profile depending on whether we actually have a
	 * profile object or not (this was created in updateProfileData)
	 */
	private void saveProfile()
	{
		if (verifyInput())
		{
			if (mProfile != null)
			{
				updateProfileData();
				mDataSource.updateVpnProfile(mProfile);
			}
			else
			{
				mProfile = new VpnProfile();
				updateProfileData();
				mDataSource.insertProfile(mProfile);
			}
			setResult(RESULT_OK, new Intent().putExtra(VpnProfileDataSource.KEY_ID, mProfile.getId()));
			finish();
		}
	}

	/**
	 * Verify the user input and display error messages.
	 * @return true if the input is valid
	 */
	private boolean verifyInput()
	{
		boolean valid = true;
		if (mGateway.getText().toString().trim().isEmpty())
		{
			mGateway.setError(getString(R.string.alert_text_no_input_gateway));
			valid = false;
		}
		if (mUsername.getText().toString().trim().isEmpty())
		{
			mUsername.setError(getString(R.string.alert_text_no_input_username));
			valid = false;
		}
		if (!mCheckAuto.isChecked() && mSelectedCert == null)
		{
			showCertificateAlert();
			valid = false;
		}
		return valid;
	}

	/**
	 * Update the profile object with the data entered by the user
	 */
	private void updateProfileData()
	{
		/* the name is optional, we default to the gateway if none is given */
		String name = mName.getText().toString().trim();
		String gateway = mGateway.getText().toString().trim();
		mProfile.setName(name.isEmpty() ? gateway : name);
		mProfile.setGateway(gateway);
		mProfile.setUsername(mUsername.getText().toString().trim());
		String password = mPassword.getText().toString().trim();
		password = password.isEmpty() ? null : password;
		mProfile.setPassword(password);
		String certAlias = mCheckAuto.isChecked() ? null : mSelectedCert.mAlias;
		mProfile.setCertificateAlias(certAlias);
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
				mCertAlias = mProfile.getCertificateAlias();
				getActionBar().setTitle(mProfile.getName());
			}
			else
			{
				Log.e(VpnProfileDetailActivity.class.getSimpleName(),
					  "VPN profile with id " + mId + " not found");
				finish();
			}
		}
		mCheckAll.setChecked(false);
		mCheckAuto.setChecked(mCertAlias == null);
		updateCertSpinner();
	}
}

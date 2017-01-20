/*
 * Copyright (C) 2012-2016 Tobias Brunner
 * Copyright (C) 2012 Giuliano Grassi
 * Copyright (C) 2012 Ralf Sager
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

import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.KeyChainException;
import android.support.v4.content.LocalBroadcastManager;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.app.AppCompatDialogFragment;
import android.text.Editable;
import android.text.Html;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.util.Log;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.ArrayAdapter;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.CompoundButton.OnCheckedChangeListener;
import android.widget.EditText;
import android.widget.MultiAutoCompleteTextView;
import android.widget.RelativeLayout;
import android.widget.Spinner;
import android.widget.TextView;

import org.strongswan.android.R;
import org.strongswan.android.data.VpnProfile;
import org.strongswan.android.data.VpnProfileDataSource;
import org.strongswan.android.data.VpnType;
import org.strongswan.android.data.VpnType.VpnTypeFeature;
import org.strongswan.android.logic.TrustedCertificateManager;
import org.strongswan.android.security.TrustedCertificateEntry;
import org.strongswan.android.ui.adapter.CertificateIdentitiesAdapter;
import org.strongswan.android.ui.widget.TextInputLayoutHelper;
import org.strongswan.android.utils.Constants;

import java.security.cert.X509Certificate;
import java.util.UUID;

public class VpnProfileDetailActivity extends AppCompatActivity
{
	private static final int SELECT_TRUSTED_CERTIFICATE = 0;

	private VpnProfileDataSource mDataSource;
	private Long mId;
	private TrustedCertificateEntry mCertEntry;
	private String mUserCertLoading;
	private CertificateIdentitiesAdapter mSelectUserIdAdapter;
	private String mSelectedUserId;
	private TrustedCertificateEntry mUserCertEntry;
	private VpnType mVpnType = VpnType.IKEV2_EAP;
	private VpnProfile mProfile;
	private MultiAutoCompleteTextView mName;
	private TextInputLayoutHelper mNameWrap;
	private EditText mGateway;
	private TextInputLayoutHelper mGatewayWrap;
	private Spinner mSelectVpnType;
	private ViewGroup mUsernamePassword;
	private EditText mUsername;
	private TextInputLayoutHelper mUsernameWrap;
	private EditText mPassword;
	private ViewGroup mUserCertificate;
	private RelativeLayout mSelectUserCert;
	private Spinner mSelectUserId;
	private CheckBox mCheckAuto;
	private RelativeLayout mSelectCert;
	private RelativeLayout mTncNotice;
	private CheckBox mShowAdvanced;
	private ViewGroup mAdvancedSettings;
	private MultiAutoCompleteTextView mRemoteId;
	private TextInputLayoutHelper mRemoteIdWrap;
	private EditText mMTU;
	private TextInputLayoutHelper mMTUWrap;
	private EditText mPort;
	private TextInputLayoutHelper mPortWrap;
	private CheckBox mBlockIPv4;
	private CheckBox mBlockIPv6;

	@Override
	public void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);

		/* the title is set when we load the profile, if any */
		getSupportActionBar().setDisplayHomeAsUpEnabled(true);

		mDataSource = new VpnProfileDataSource(this);
		mDataSource.open();

		setContentView(R.layout.profile_detail_view);

		mName = (MultiAutoCompleteTextView)findViewById(R.id.name);
		mNameWrap = (TextInputLayoutHelper)findViewById(R.id.name_wrap);
		mGateway = (EditText)findViewById(R.id.gateway);
		mGatewayWrap = (TextInputLayoutHelper) findViewById(R.id.gateway_wrap);
		mSelectVpnType = (Spinner)findViewById(R.id.vpn_type);
		mTncNotice = (RelativeLayout)findViewById(R.id.tnc_notice);

		mUsernamePassword = (ViewGroup)findViewById(R.id.username_password_group);
		mUsername = (EditText)findViewById(R.id.username);
		mUsernameWrap = (TextInputLayoutHelper) findViewById(R.id.username_wrap);
		mPassword = (EditText)findViewById(R.id.password);

		mUserCertificate = (ViewGroup)findViewById(R.id.user_certificate_group);
		mSelectUserCert = (RelativeLayout)findViewById(R.id.select_user_certificate);
		mSelectUserId = (Spinner)findViewById(R.id.select_user_id);

		mCheckAuto = (CheckBox)findViewById(R.id.ca_auto);
		mSelectCert = (RelativeLayout)findViewById(R.id.select_certificate);

		mShowAdvanced = (CheckBox)findViewById(R.id.show_advanced);
		mAdvancedSettings = (ViewGroup)findViewById(R.id.advanced_settings);

		mRemoteId = (MultiAutoCompleteTextView)findViewById(R.id.remote_id);
		mRemoteIdWrap = (TextInputLayoutHelper) findViewById(R.id.remote_id_wrap);
		mMTU = (EditText)findViewById(R.id.mtu);
		mMTUWrap = (TextInputLayoutHelper) findViewById(R.id.mtu_wrap);
		mPort = (EditText)findViewById(R.id.port);
		mPortWrap = (TextInputLayoutHelper) findViewById(R.id.port_wrap);
		mBlockIPv4 = (CheckBox)findViewById(R.id.split_tunneling_v4);
		mBlockIPv6 = (CheckBox)findViewById(R.id.split_tunneling_v6);

		final SpaceTokenizer spaceTokenizer = new SpaceTokenizer();
		mName.setTokenizer(spaceTokenizer);
		mRemoteId.setTokenizer(spaceTokenizer);
		final ArrayAdapter<String> completeAdapter = new ArrayAdapter<>(this, android.R.layout.simple_dropdown_item_1line);
		mName.setAdapter(completeAdapter);
		mRemoteId.setAdapter(completeAdapter);

		mGateway.addTextChangedListener(new TextWatcher() {
			@Override
			public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

			@Override
			public void onTextChanged(CharSequence s, int start, int before, int count) {}

			@Override
			public void afterTextChanged(Editable s)
			{
				completeAdapter.clear();
				completeAdapter.add(mGateway.getText().toString());
				if (TextUtils.isEmpty(mGateway.getText()))
				{
					mNameWrap.setHelperText(getString(R.string.profile_name_hint));
					mRemoteIdWrap.setHelperText(getString(R.string.profile_remote_id_hint));
				}
				else
				{
					mNameWrap.setHelperText(String.format(getString(R.string.profile_name_hint_gateway), mGateway.getText()));
					mRemoteIdWrap.setHelperText(String.format(getString(R.string.profile_remote_id_hint_gateway), mGateway.getText()));
				}
			}
		});

		mSelectVpnType.setOnItemSelectedListener(new OnItemSelectedListener() {
			@Override
			public void onItemSelected(AdapterView<?> parent, View view, int position, long id)
			{
				mVpnType = VpnType.values()[position];
				updateCredentialView();
			}

			@Override
			public void onNothingSelected(AdapterView<?> parent)
			{	/* should not happen */
				mVpnType = VpnType.IKEV2_EAP;
				updateCredentialView();
			}
		});

		((TextView)mTncNotice.findViewById(android.R.id.text1)).setText(R.string.tnc_notice_title);
		((TextView)mTncNotice.findViewById(android.R.id.text2)).setText(R.string.tnc_notice_subtitle);
		mTncNotice.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View v)
			{
				new TncNoticeDialog().show(VpnProfileDetailActivity.this.getSupportFragmentManager(), "TncNotice");
			}
		});

		mSelectUserCert.setOnClickListener(new SelectUserCertOnClickListener());
		mSelectUserIdAdapter = new CertificateIdentitiesAdapter(this);
		mSelectUserId.setAdapter(mSelectUserIdAdapter);
		mSelectUserId.setOnItemSelectedListener(new OnItemSelectedListener() {
			@Override
			public void onItemSelected(AdapterView<?> parent, View view, int position, long id)
			{
				if (mUserCertEntry != null)
				{	/* we don't store the subject DN as it is in the reverse order and the default anyway */
					mSelectedUserId = position == 0 ? null : mSelectUserIdAdapter.getItem(position);
				}
			}

			@Override
			public void onNothingSelected(AdapterView<?> parent)
			{
				mSelectedUserId = null;
			}
		});

		mCheckAuto.setOnCheckedChangeListener(new OnCheckedChangeListener() {
			@Override
			public void onCheckedChanged(CompoundButton buttonView, boolean isChecked)
			{
				updateCertificateSelector();
			}
		});

		mSelectCert.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View v)
			{
				Intent intent = new Intent(VpnProfileDetailActivity.this, TrustedCertificatesActivity.class);
				intent.setAction(TrustedCertificatesActivity.SELECT_CERTIFICATE);
				startActivityForResult(intent, SELECT_TRUSTED_CERTIFICATE);
			}
		});

		mShowAdvanced.setOnCheckedChangeListener(new OnCheckedChangeListener() {
			@Override
			public void onCheckedChanged(CompoundButton buttonView, boolean isChecked)
			{
				updateAdvancedSettings();
			}
		});

		mId = savedInstanceState == null ? null : savedInstanceState.getLong(VpnProfileDataSource.KEY_ID);
		if (mId == null)
		{
			Bundle extras = getIntent().getExtras();
			mId = extras == null ? null : extras.getLong(VpnProfileDataSource.KEY_ID);
		}

		loadProfileData(savedInstanceState);

		updateCredentialView();
		updateCertificateSelector();
		updateAdvancedSettings();
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
		if (mId != null)
		{
			outState.putLong(VpnProfileDataSource.KEY_ID, mId);
		}
		if (mUserCertEntry != null)
		{
			outState.putString(VpnProfileDataSource.KEY_USER_CERTIFICATE, mUserCertEntry.getAlias());
		}
		if (mSelectedUserId != null)
		{
			outState.putString(VpnProfileDataSource.KEY_LOCAL_ID, mSelectedUserId);
		}
		if (mCertEntry != null)
		{
			outState.putString(VpnProfileDataSource.KEY_CERTIFICATE, mCertEntry.getAlias());
		}
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

	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data)
	{
		switch (requestCode)
		{
			case SELECT_TRUSTED_CERTIFICATE:
				if (resultCode == RESULT_OK)
				{
					String alias = data.getStringExtra(VpnProfileDataSource.KEY_CERTIFICATE);
					X509Certificate certificate = TrustedCertificateManager.getInstance().getCACertificateFromAlias(alias);
					mCertEntry = certificate == null ? null : new TrustedCertificateEntry(alias, certificate);
					updateCertificateSelector();
				}
				break;
			default:
				super.onActivityResult(requestCode, resultCode, data);
		}
	}

	/**
	 * Update the UI to enter credentials depending on the type of VPN currently selected
	 */
	private void updateCredentialView()
	{
		mUsernamePassword.setVisibility(mVpnType.has(VpnTypeFeature.USER_PASS) ? View.VISIBLE : View.GONE);
		mUserCertificate.setVisibility(mVpnType.has(VpnTypeFeature.CERTIFICATE) ? View.VISIBLE : View.GONE);
		mTncNotice.setVisibility(mVpnType.has(VpnTypeFeature.BYOD) ? View.VISIBLE : View.GONE);

		if (mVpnType.has(VpnTypeFeature.CERTIFICATE))
		{
			mSelectUserId.setEnabled(false);
			if (mUserCertLoading != null)
			{
				((TextView)mSelectUserCert.findViewById(android.R.id.text1)).setText(mUserCertLoading);
				((TextView)mSelectUserCert.findViewById(android.R.id.text2)).setText(R.string.loading);
			}
			else if (mUserCertEntry != null)
			{	/* clear any errors and set the new data */
				((TextView)mSelectUserCert.findViewById(android.R.id.text1)).setError(null);
				((TextView)mSelectUserCert.findViewById(android.R.id.text1)).setText(mUserCertEntry.getAlias());
				((TextView)mSelectUserCert.findViewById(android.R.id.text2)).setText(mUserCertEntry.getCertificate().getSubjectDN().toString());
				mSelectUserIdAdapter.setCertificate(mUserCertEntry);
				mSelectUserId.setSelection(mSelectUserIdAdapter.getPosition(mSelectedUserId));
				mSelectUserId.setEnabled(true);
			}
			else
			{
				((TextView)mSelectUserCert.findViewById(android.R.id.text1)).setText(R.string.profile_user_select_certificate_label);
				((TextView)mSelectUserCert.findViewById(android.R.id.text2)).setText(R.string.profile_user_select_certificate);
				mSelectUserIdAdapter.setCertificate(null);
			}
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
	 * Update the CA certificate selection UI depending on whether the
	 * certificate should be automatically selected or not.
	 */
	private void updateCertificateSelector()
	{
		if (!mCheckAuto.isChecked())
		{
			mSelectCert.setEnabled(true);
			mSelectCert.setVisibility(View.VISIBLE);

			if (mCertEntry != null)
			{
				((TextView)mSelectCert.findViewById(android.R.id.text1)).setText(mCertEntry.getSubjectPrimary());
				((TextView)mSelectCert.findViewById(android.R.id.text2)).setText(mCertEntry.getSubjectSecondary());
			}
			else
			{
				((TextView)mSelectCert.findViewById(android.R.id.text1)).setText(R.string.profile_ca_select_certificate_label);
				((TextView)mSelectCert.findViewById(android.R.id.text2)).setText(R.string.profile_ca_select_certificate);
			}
		}
		else
		{
			mSelectCert.setEnabled(false);
			mSelectCert.setVisibility(View.GONE);
		}
	}

	/**
	 * Update the advanced settings UI depending on whether any advanced
	 * settings have already been made.
	 */
	private void updateAdvancedSettings()
	{
		boolean show = mShowAdvanced.isChecked();
		if (!show && mProfile != null)
		{
			Integer st = mProfile.getSplitTunneling();
			show = mProfile.getRemoteId() != null || mProfile.getMTU() != null ||
				   mProfile.getPort() != null || (st != null && st != 0);
		}
		mShowAdvanced.setVisibility(!show ? View.VISIBLE : View.GONE);
		mAdvancedSettings.setVisibility(show ? View.VISIBLE : View.GONE);
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
				if (mProfile.getUUID() == null)
				{
					mProfile.setUUID(UUID.randomUUID());
				}
				mDataSource.updateVpnProfile(mProfile);
			}
			else
			{
				mProfile = new VpnProfile();
				updateProfileData();
				mDataSource.insertProfile(mProfile);
			}
			Intent intent = new Intent(Constants.VPN_PROFILES_CHANGED);
			intent.putExtra(Constants.VPN_PROFILES_SINGLE, mProfile.getId());
			LocalBroadcastManager.getInstance(this).sendBroadcast(intent);

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
			mGatewayWrap.setError(getString(R.string.alert_text_no_input_gateway));
			valid = false;
		}
		if (mVpnType.has(VpnTypeFeature.USER_PASS))
		{
			if (mUsername.getText().toString().trim().isEmpty())
			{
				mUsernameWrap.setError(getString(R.string.alert_text_no_input_username));
				valid = false;
			}
		}
		if (mVpnType.has(VpnTypeFeature.CERTIFICATE) && mUserCertEntry == null)
		{	/* let's show an error icon */
			((TextView)mSelectUserCert.findViewById(android.R.id.text1)).setError("");
			valid = false;
		}
		if (!mCheckAuto.isChecked() && mCertEntry == null)
		{
			showCertificateAlert();
			valid = false;
		}
		if (!validateInteger(mMTU, Constants.MTU_MIN, Constants.MTU_MAX))
		{
			mMTUWrap.setError(String.format(getString(R.string.alert_text_out_of_range), Constants.MTU_MIN, Constants.MTU_MAX));
			valid = false;
		}
		if (!validateInteger(mPort, 1, 65535))
		{
			mPortWrap.setError(String.format(getString(R.string.alert_text_out_of_range), 1, 65535));
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
		mProfile.setVpnType(mVpnType);
		if (mVpnType.has(VpnTypeFeature.USER_PASS))
		{
			mProfile.setUsername(mUsername.getText().toString().trim());
			String password = mPassword.getText().toString().trim();
			password = password.isEmpty() ? null : password;
			mProfile.setPassword(password);
		}
		if (mVpnType.has(VpnTypeFeature.CERTIFICATE))
		{
			mProfile.setUserCertificateAlias(mUserCertEntry.getAlias());
			mProfile.setLocalId(mSelectedUserId);
		}
		String certAlias = mCheckAuto.isChecked() ? null : mCertEntry.getAlias();
		mProfile.setCertificateAlias(certAlias);
		String remote_id = mRemoteId.getText().toString().trim();
		mProfile.setRemoteId(remote_id.isEmpty() ? null : remote_id);
		mProfile.setMTU(getInteger(mMTU));
		mProfile.setPort(getInteger(mPort));
		int st = 0;
		st |= mBlockIPv4.isChecked() ? VpnProfile.SPLIT_TUNNELING_BLOCK_IPV4 : 0;
		st |= mBlockIPv6.isChecked() ? VpnProfile.SPLIT_TUNNELING_BLOCK_IPV6 : 0;
		mProfile.setSplitTunneling(st == 0 ? null : st);
	}

	/**
	 * Load an existing profile if we got an ID
	 *
	 * @param savedInstanceState previously saved state
	 */
	private void loadProfileData(Bundle savedInstanceState)
	{
		String useralias = null, local_id = null, alias = null;

		getSupportActionBar().setTitle(R.string.add_profile);
		if (mId != null && mId != 0)
		{
			mProfile = mDataSource.getVpnProfile(mId);
			if (mProfile != null)
			{
				mName.setText(mProfile.getName());
				mGateway.setText(mProfile.getGateway());
				mVpnType = mProfile.getVpnType();
				mUsername.setText(mProfile.getUsername());
				mPassword.setText(mProfile.getPassword());
				mRemoteId.setText(mProfile.getRemoteId());
				mMTU.setText(mProfile.getMTU() != null ? mProfile.getMTU().toString() : null);
				mPort.setText(mProfile.getPort() != null ? mProfile.getPort().toString() : null);
				mBlockIPv4.setChecked(mProfile.getSplitTunneling() != null && (mProfile.getSplitTunneling() & VpnProfile.SPLIT_TUNNELING_BLOCK_IPV4) != 0);
				mBlockIPv6.setChecked(mProfile.getSplitTunneling() != null && (mProfile.getSplitTunneling() & VpnProfile.SPLIT_TUNNELING_BLOCK_IPV6) != 0);
				useralias = mProfile.getUserCertificateAlias();
				local_id = mProfile.getLocalId();
				alias = mProfile.getCertificateAlias();
				getSupportActionBar().setTitle(mProfile.getName());
			}
			else
			{
				Log.e(VpnProfileDetailActivity.class.getSimpleName(),
					  "VPN profile with id " + mId + " not found");
				finish();
			}
		}

		mSelectVpnType.setSelection(mVpnType.ordinal());

		/* check if the user selected a user certificate previously */
		useralias = savedInstanceState == null ? useralias : savedInstanceState.getString(VpnProfileDataSource.KEY_USER_CERTIFICATE);
		local_id = savedInstanceState == null ? local_id : savedInstanceState.getString(VpnProfileDataSource.KEY_LOCAL_ID);
		if (useralias != null)
		{
			UserCertificateLoader loader = new UserCertificateLoader(this, useralias);
			mUserCertLoading = useralias;
			mSelectedUserId = local_id;
			loader.execute();
		}

		/* check if the user selected a CA certificate previously */
		alias = savedInstanceState == null ? alias : savedInstanceState.getString(VpnProfileDataSource.KEY_CERTIFICATE);
		mCheckAuto.setChecked(alias == null);
		if (alias != null)
		{
			X509Certificate certificate = TrustedCertificateManager.getInstance().getCACertificateFromAlias(alias);
			if (certificate != null)
			{
				mCertEntry = new TrustedCertificateEntry(alias, certificate);
			}
			else
			{	/* previously selected certificate is not here anymore */
				showCertificateAlert();
				mCertEntry = null;
			}
		}
	}

	/**
	 * Get the integer value in the given text box or null if empty
	 *
	 * @param view text box (numeric entry assumed)
	 */
	private Integer getInteger(EditText view)
	{
		String value = view.getText().toString().trim();
		try
		{
			return value.isEmpty() ? null : Integer.valueOf(value);
		}
		catch (NumberFormatException e)
		{
			return null;
		}
	}

	/**
	 * Check that the value in the given text box is a valid integer in the given range
	 *
	 * @param view text box (numeric entry assumed)
	 * @param min minimum value (inclusive)
	 * @param max maximum value (inclusive)
	 */
	private boolean validateInteger(EditText view, Integer min, Integer max)
	{
		String value = view.getText().toString().trim();
		try
		{
			if (value.isEmpty())
			{
				return true;
			}
			Integer val = Integer.valueOf(value);
			return min <= val && val <= max;
		}
		catch (NumberFormatException e)
		{
			return false;
		}
	}

	private class SelectUserCertOnClickListener implements OnClickListener, KeyChainAliasCallback
	{
		@Override
		public void onClick(View v)
		{
			String useralias = mUserCertEntry != null ? mUserCertEntry.getAlias() : null;
			KeyChain.choosePrivateKeyAlias(VpnProfileDetailActivity.this, this, new String[] { "RSA" }, null, null, -1, useralias);
		}

		@Override
		public void alias(final String alias)
		{
			if (alias != null)
			{	/* otherwise the dialog was canceled, the request denied */
				try
				{
					final X509Certificate[] chain = KeyChain.getCertificateChain(VpnProfileDetailActivity.this, alias);
					/* alias() is not called from our main thread */
					runOnUiThread(new Runnable() {
						@Override
						public void run()
						{
							if (chain != null && chain.length > 0)
							{
								mUserCertEntry = new TrustedCertificateEntry(alias, chain[0]);
							}
							updateCredentialView();
						}
					});
				}
				catch (KeyChainException | InterruptedException e)
				{
					e.printStackTrace();
				}
			}
		}
	}

	/**
	 * Load the selected user certificate asynchronously.  This cannot be done
	 * from the main thread as getCertificateChain() calls back to our main
	 * thread to bind to the KeyChain service resulting in a deadlock.
	 */
	private class UserCertificateLoader extends AsyncTask<Void, Void, X509Certificate>
	{
		private final Context mContext;
		private final String mAlias;

		public UserCertificateLoader(Context context, String alias)
		{
			mContext = context;
			mAlias = alias;
		}

		@Override
		protected X509Certificate doInBackground(Void... params)
		{
			X509Certificate[] chain = null;
			try
			{
				chain = KeyChain.getCertificateChain(mContext, mAlias);
			}
			catch (KeyChainException | InterruptedException e)
			{
				e.printStackTrace();
			}
			if (chain != null && chain.length > 0)
			{
				return chain[0];
			}
			return null;
		}

		@Override
		protected void onPostExecute(X509Certificate result)
		{
			if (result != null)
			{
				mUserCertEntry = new TrustedCertificateEntry(mAlias, result);
			}
			else
			{	/* previously selected certificate is not here anymore */
				((TextView)mSelectUserCert.findViewById(android.R.id.text1)).setError("");
				mUserCertEntry = null;
			}
			mUserCertLoading = null;
			updateCredentialView();
		}
	}

	/**
	 * Dialog with notification message if EAP-TNC is used.
	 */
	public static class TncNoticeDialog extends AppCompatDialogFragment
	{
		@Override
		public Dialog onCreateDialog(Bundle savedInstanceState)
		{
			return new AlertDialog.Builder(getActivity())
				.setTitle(R.string.tnc_notice_title)
				.setMessage(Html.fromHtml(getString(R.string.tnc_notice_details)))
				.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
					@Override
					public void onClick(DialogInterface dialog, int id)
					{
						dialog.dismiss();
					}
				}).create();
		}
	}

	/**
	 * Tokenizer implementation that separates by white-space
	 */
	public static class SpaceTokenizer implements MultiAutoCompleteTextView.Tokenizer
	{
		@Override
		public int findTokenStart(CharSequence text, int cursor)
		{
			int i = cursor;

			while (i > 0 && !Character.isWhitespace(text.charAt(i - 1)))
			{
				i--;
			}
			return i;
		}

		@Override
		public int findTokenEnd(CharSequence text, int cursor)
		{
			int i = cursor;
			int len = text.length();

			while (i < len)
			{
				if (Character.isWhitespace(text.charAt(i)))
				{
					return i;
				}
				else
				{
					i++;
				}
			}
			return len;
		}

		@Override
		public CharSequence terminateToken(CharSequence text)
		{
			int i = text.length();

			if (i > 0 && Character.isWhitespace(text.charAt(i - 1)))
			{
				return text;
			}
			else
			{
				if (text instanceof Spanned)
				{
					SpannableString sp = new SpannableString(text + " ");
					TextUtils.copySpansFrom((Spanned) text, 0, text.length(), Object.class, sp, 0);
					return sp;
				}
				else
				{
					return text + " ";
				}
			}
		}
	}
}

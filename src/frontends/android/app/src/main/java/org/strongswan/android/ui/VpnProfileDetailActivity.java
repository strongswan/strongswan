/*
 * Copyright (C) 2023 Relution GmbH
 * Copyright (C) 2012-2020 Tobias Brunner
 * Copyright (C) 2012 Giuliano Grassi
 * Copyright (C) 2012 Ralf Sager
 *
 * Copyright (C) secunet Security Networks AG
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
import android.os.Bundle;
import android.os.Handler;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.security.KeyChainException;
import android.text.Editable;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.text.method.LinkMovementMethod;
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
import org.strongswan.android.data.VpnProfile.SelectedAppsHandling;
import org.strongswan.android.data.VpnProfileDataSource;
import org.strongswan.android.data.VpnProfileSource;
import org.strongswan.android.data.VpnType;
import org.strongswan.android.data.VpnType.VpnTypeFeature;
import org.strongswan.android.logic.StrongSwanApplication;
import org.strongswan.android.logic.TrustedCertificateManager;
import org.strongswan.android.security.TrustedCertificateEntry;
import org.strongswan.android.ui.adapter.CertificateIdentitiesAdapter;
import org.strongswan.android.ui.widget.TextInputLayoutHelper;
import org.strongswan.android.utils.Constants;
import org.strongswan.android.utils.IPRangeSet;
import org.strongswan.android.utils.Utils;

import java.net.UnknownHostException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.UUID;
import java.util.concurrent.Executor;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.app.AppCompatDialogFragment;
import androidx.appcompat.widget.SwitchCompat;
import androidx.core.text.HtmlCompat;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

public class VpnProfileDetailActivity extends AppCompatActivity
{
	private VpnProfileDataSource mDataSource;
	private String mUuid;
	private TrustedCertificateEntry mCertEntry;
	private String mUserCertLoading;
	private CertificateIdentitiesAdapter mSelectUserIdAdapter;
	private TrustedCertificateEntry mUserCertEntry;
	private VpnType mVpnType = VpnType.IKEV2_EAP;
	private SelectedAppsHandling mSelectedAppsHandling = SelectedAppsHandling.SELECTED_APPS_DISABLE;
	private SortedSet<String> mSelectedApps = new TreeSet<>();
	private VpnProfile mProfile;
	private View mManagedProfile;
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
	private CheckBox mCheckAuto;
	private RelativeLayout mSelectCert;
	private RelativeLayout mTncNotice;
	private CheckBox mShowAdvanced;
	private ViewGroup mAdvancedSettings;
	private MultiAutoCompleteTextView mRemoteId;
	private TextInputLayoutHelper mRemoteIdWrap;
	private MultiAutoCompleteTextView mLocalId;
	private TextInputLayoutHelper mLocalIdWrap;
	private EditText mMTU;
	private TextInputLayoutHelper mMTUWrap;
	private EditText mPort;
	private TextInputLayoutHelper mPortWrap;
	private SwitchCompat mCertReq;
	private SwitchCompat mUseCrl;
	private SwitchCompat mUseOcsp;
	private SwitchCompat mStrictRevocation;
	private SwitchCompat mRsaPss;
	private SwitchCompat mIPv6Transport;
	private EditText mNATKeepalive;
	private TextInputLayoutHelper mNATKeepaliveWrap;
	private EditText mIncludedSubnets;
	private TextInputLayoutHelper mIncludedSubnetsWrap;
	private EditText mExcludedSubnets;
	private TextInputLayoutHelper mExcludedSubnetsWrap;
	private CheckBox mBlockIPv4;
	private CheckBox mBlockIPv6;
	private Spinner mSelectSelectedAppsHandling;
	private RelativeLayout mSelectApps;
	private TextInputLayoutHelper mIkeProposalWrap;
	private EditText mIkeProposal;
	private TextInputLayoutHelper mEspProposalWrap;
	private EditText mEspProposal;
	private TextView mProfileIdLabel;
	private TextView mProfileId;
	private EditText mDnsServers;
	private TextInputLayoutHelper mDnsServersWrap;

	private final ActivityResultLauncher<Intent> mInstallPKCS12 = registerForActivityResult(
		new ActivityResultContracts.StartActivityForResult(),
		result -> {
			if (result.getResultCode() == RESULT_OK)
			{
				mSelectUserCert.performClick();
			}
		}
	);

	private final ActivityResultLauncher<Intent> mSelectTrustedCertificate = registerForActivityResult(
		new ActivityResultContracts.StartActivityForResult(),
		result -> {
			if (result.getResultCode() == RESULT_OK)
			{
				String alias = result.getData().getStringExtra(VpnProfileDataSource.KEY_CERTIFICATE);
				X509Certificate certificate = TrustedCertificateManager.getInstance().getCACertificateFromAlias(alias);
				mCertEntry = certificate == null ? null : new TrustedCertificateEntry(alias, certificate);
				updateCertificateSelector();
			}
		}
	);

	private final ActivityResultLauncher<Intent> mSelectApplications = registerForActivityResult(
		new ActivityResultContracts.StartActivityForResult(),
		result -> {
			if (result.getResultCode() == RESULT_OK)
			{
				ArrayList<String> selection = result.getData().getStringArrayListExtra(VpnProfileDataSource.KEY_SELECTED_APPS_LIST);
				mSelectedApps = new TreeSet<>(selection);
				updateAppsSelector();
			}
		}
	);

	@Override
	public void onCreate(Bundle savedInstanceState)
	{
		super.onCreate(savedInstanceState);

		/* the title is set when we load the profile, if any */
		getSupportActionBar().setDisplayHomeAsUpEnabled(true);

		mDataSource = new VpnProfileSource(this);
		mDataSource.open();

		setContentView(R.layout.profile_detail_view);

		mManagedProfile = findViewById(R.id.managed_profile);

		mName = findViewById(R.id.name);
		mNameWrap = findViewById(R.id.name_wrap);
		mGateway = findViewById(R.id.gateway);
		mGatewayWrap = findViewById(R.id.gateway_wrap);
		mSelectVpnType = findViewById(R.id.vpn_type);
		mTncNotice = findViewById(R.id.tnc_notice);

		mUsernamePassword = findViewById(R.id.username_password_group);
		mUsername = findViewById(R.id.username);
		mUsernameWrap = findViewById(R.id.username_wrap);
		mPassword = findViewById(R.id.password);

		mUserCertificate = findViewById(R.id.user_certificate_group);
		mSelectUserCert = findViewById(R.id.select_user_certificate);

		mCheckAuto = findViewById(R.id.ca_auto);
		mSelectCert = findViewById(R.id.select_certificate);

		mShowAdvanced = findViewById(R.id.show_advanced);
		mAdvancedSettings = findViewById(R.id.advanced_settings);

		mRemoteId = findViewById(R.id.remote_id);
		mRemoteIdWrap = findViewById(R.id.remote_id_wrap);
		mLocalId = findViewById(R.id.local_id);
		mLocalIdWrap = findViewById(R.id.local_id_wrap);
		mDnsServers = findViewById(R.id.dns_servers);
		mDnsServersWrap = findViewById(R.id.dns_servers_wrap);
		mMTU = findViewById(R.id.mtu);
		mMTUWrap = findViewById(R.id.mtu_wrap);
		mPort = findViewById(R.id.port);
		mPortWrap = findViewById(R.id.port_wrap);
		mNATKeepalive = findViewById(R.id.nat_keepalive);
		mNATKeepaliveWrap = findViewById(R.id.nat_keepalive_wrap);
		mCertReq = findViewById(R.id.cert_req);
		mUseCrl = findViewById(R.id.use_crl);
		mUseOcsp = findViewById(R.id.use_ocsp);
		mStrictRevocation = findViewById(R.id.strict_revocation);
		mRsaPss = findViewById(R.id.rsa_pss);
		mIPv6Transport = findViewById(R.id.ipv6_transport);
		mIncludedSubnets = findViewById(R.id.included_subnets);
		mIncludedSubnetsWrap = findViewById(R.id.included_subnets_wrap);
		mExcludedSubnets = findViewById(R.id.excluded_subnets);
		mExcludedSubnetsWrap = findViewById(R.id.excluded_subnets_wrap);
		mBlockIPv4 = findViewById(R.id.split_tunneling_v4);
		mBlockIPv6 = findViewById(R.id.split_tunneling_v6);

		mSelectSelectedAppsHandling = findViewById(R.id.apps_handling);
		mSelectApps = findViewById(R.id.select_applications);

		mIkeProposal = findViewById(R.id.ike_proposal);
		mIkeProposalWrap = findViewById(R.id.ike_proposal_wrap);
		mEspProposal = findViewById(R.id.esp_proposal);
		mEspProposalWrap = findViewById(R.id.esp_proposal_wrap);
		/* make the link clickable */
		((TextView)findViewById(R.id.proposal_intro)).setMovementMethod(LinkMovementMethod.getInstance());

		mProfileIdLabel = findViewById(R.id.profile_id_label);
		mProfileId = findViewById(R.id.profile_id);

		final SpaceTokenizer spaceTokenizer = new SpaceTokenizer();
		mName.setTokenizer(spaceTokenizer);
		mRemoteId.setTokenizer(spaceTokenizer);
		mLocalId.setTokenizer(spaceTokenizer);
		final ArrayAdapter<String> gatewayAdapter = new ArrayAdapter<>(this, android.R.layout.simple_dropdown_item_1line);
		mName.setAdapter(gatewayAdapter);
		mRemoteId.setAdapter(gatewayAdapter);

		mGateway.addTextChangedListener(new TextWatcher()
		{
			@Override
			public void beforeTextChanged(CharSequence s, int start, int count, int after) {}

			@Override
			public void onTextChanged(CharSequence s, int start, int before, int count) {}

			@Override
			public void afterTextChanged(Editable s)
			{
				gatewayAdapter.clear();
				gatewayAdapter.add(mGateway.getText().toString());
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

		mSelectVpnType.setOnItemSelectedListener(new OnItemSelectedListener()
		{
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
		mTncNotice.setOnClickListener(new OnClickListener()
		{
			@Override
			public void onClick(View v)
			{
				new TncNoticeDialog().show(VpnProfileDetailActivity.this.getSupportFragmentManager(), "TncNotice");
			}
		});

		mSelectUserCert.setOnClickListener(new SelectUserCertOnClickListener());
		findViewById(R.id.install_user_certificate).setOnClickListener(v -> {
			Intent intent = KeyChain.createInstallIntent();
			mInstallPKCS12.launch(intent);
		});
		mSelectUserIdAdapter = new CertificateIdentitiesAdapter(this);
		mLocalId.setAdapter(mSelectUserIdAdapter);

		mCheckAuto.setOnCheckedChangeListener(new OnCheckedChangeListener()
		{
			@Override
			public void onCheckedChanged(CompoundButton buttonView, boolean isChecked)
			{
				updateCertificateSelector();
			}
		});

		mSelectCert.setOnClickListener(new OnClickListener()
		{
			@Override
			public void onClick(View v)
			{
				Intent intent = new Intent(VpnProfileDetailActivity.this, TrustedCertificatesActivity.class);
				intent.setAction(TrustedCertificatesActivity.SELECT_CERTIFICATE);
				mSelectTrustedCertificate.launch(intent);
			}
		});

		mShowAdvanced.setOnCheckedChangeListener(new OnCheckedChangeListener()
		{
			@Override
			public void onCheckedChanged(CompoundButton buttonView, boolean isChecked)
			{
				updateAdvancedSettings();
			}
		});

		mSelectSelectedAppsHandling.setOnItemSelectedListener(new OnItemSelectedListener()
		{
			@Override
			public void onItemSelected(AdapterView<?> parent, View view, int position, long id)
			{
				mSelectedAppsHandling = SelectedAppsHandling.values()[position];
				updateAppsSelector();
			}

			@Override
			public void onNothingSelected(AdapterView<?> parent)
			{	/* should not happen */
				mSelectedAppsHandling = SelectedAppsHandling.SELECTED_APPS_DISABLE;
				updateAppsSelector();
			}
		});

		mSelectApps.setOnClickListener(new OnClickListener()
		{
			@Override
			public void onClick(View v)
			{
				Intent intent = new Intent(VpnProfileDetailActivity.this, SelectedApplicationsActivity.class);
				intent.putExtra(VpnProfileDataSource.KEY_SELECTED_APPS_LIST, new ArrayList<>(mSelectedApps));
				intent.putExtra(VpnProfileDataSource.KEY_READ_ONLY, mProfile.isReadOnly());
				mSelectApplications.launch(intent);
			}
		});

		mUuid = savedInstanceState == null ? null : savedInstanceState.getString(VpnProfileDataSource.KEY_UUID);
		if (mUuid == null)
		{
			Bundle extras = getIntent().getExtras();
			mUuid = extras == null ? null : extras.getString(VpnProfileDataSource.KEY_UUID);
		}

		loadProfileData(savedInstanceState);

		updateCredentialView();
		updateCertificateSelector();
		updateAdvancedSettings();
		updateAppsSelector();
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
		if (mUuid != null)
		{
			outState.putString(VpnProfileDataSource.KEY_UUID, mUuid);
		}
		if (mUserCertEntry != null)
		{
			outState.putString(VpnProfileDataSource.KEY_USER_CERTIFICATE, mUserCertEntry.getAlias());
		}
		if (mCertEntry != null)
		{
			outState.putString(VpnProfileDataSource.KEY_CERTIFICATE, mCertEntry.getAlias());
		}
		outState.putStringArrayList(VpnProfileDataSource.KEY_SELECTED_APPS_LIST, new ArrayList<>(mSelectedApps));
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
	 * Update the UI to enter credentials depending on the type of VPN currently selected
	 */
	private void updateCredentialView()
	{
		mUsernamePassword.setVisibility(mVpnType.has(VpnTypeFeature.USER_PASS) ? View.VISIBLE : View.GONE);
		mUserCertificate.setVisibility(mVpnType.has(VpnTypeFeature.CERTIFICATE) ? View.VISIBLE : View.GONE);
		mTncNotice.setVisibility(mVpnType.has(VpnTypeFeature.BYOD) ? View.VISIBLE : View.GONE);
		mLocalIdWrap.setHelperText(getString(R.string.profile_local_id_hint_user));

		if (mVpnType.has(VpnTypeFeature.CERTIFICATE))
		{
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
			}
			else
			{
				((TextView)mSelectUserCert.findViewById(android.R.id.text1)).setText(R.string.profile_user_select_certificate_label);
				((TextView)mSelectUserCert.findViewById(android.R.id.text2)).setText(R.string.profile_user_select_certificate);
				mSelectUserIdAdapter.setCertificate(null);
			}
			mLocalIdWrap.setHelperText(getString(R.string.profile_local_id_hint_cert));
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
		adb.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener()
		{
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
	 * Update the application selection UI
	 */
	private void updateAppsSelector()
	{
		if (mSelectedAppsHandling == SelectedAppsHandling.SELECTED_APPS_DISABLE)
		{
			mSelectApps.setEnabled(false);
			mSelectApps.setVisibility(View.GONE);

		}
		else
		{
			mSelectApps.setEnabled(true);
			mSelectApps.setVisibility(View.VISIBLE);

			((TextView)mSelectApps.findViewById(android.R.id.text1)).setText(R.string.profile_select_apps);
			String selected;
			switch (mSelectedApps.size())
			{
				case 0:
					selected = getString(R.string.profile_select_no_apps);
					break;
				case 1:
					selected = getString(R.string.profile_select_one_app);
					break;
				default:
					selected = getString(R.string.profile_select_x_apps, mSelectedApps.size());
					break;
			}
			((TextView)mSelectApps.findViewById(android.R.id.text2)).setText(selected);
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
			Integer st = mProfile.getSplitTunneling(), flags = mProfile.getFlags();
			show = mProfile.getRemoteId() != null || mProfile.getMTU() != null ||
				   mProfile.getPort() != null || mProfile.getNATKeepAlive() != null ||
				   (flags != null && flags != 0) || (st != null && st != 0) ||
				   mProfile.getIncludedSubnets() != null || mProfile.getExcludedSubnets() != null ||
				   mProfile.getSelectedAppsHandling() != SelectedAppsHandling.SELECTED_APPS_DISABLE ||
				   mProfile.getIkeProposal() != null || mProfile.getEspProposal() != null ||
				   mProfile.getDnsServers() != null || mProfile.getLocalId() != null;
		}
		mShowAdvanced.setVisibility(!show ? View.VISIBLE : View.GONE);
		mAdvancedSettings.setVisibility(show ? View.VISIBLE : View.GONE);

		if (show && mProfile == null)
		{
			mProfileIdLabel.setVisibility(View.GONE);
			mProfileId.setVisibility(View.GONE);
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
			intent.putExtra(Constants.VPN_PROFILES_SINGLE, mProfile.getUUID().toString());
			LocalBroadcastManager.getInstance(this).sendBroadcast(intent);

			setResult(RESULT_OK, new Intent().putExtra(VpnProfileDataSource.KEY_UUID, mProfile.getUUID().toString()));
			finish();
		}
	}

	/**
	 * Verify the user input and display error messages.
	 *
	 * @return true if the input is valid
	 */
	private boolean verifyInput()
	{
		boolean valid = true;
		if (getString(mGateway) == null)
		{
			mGatewayWrap.setError(getString(R.string.alert_text_no_input_gateway));
			valid = false;
		}
		if (mVpnType.has(VpnTypeFeature.USER_PASS))
		{
			if (getString(mUsername) == null)
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
		if (!validateSubnets(mIncludedSubnets))
		{
			mIncludedSubnetsWrap.setError(getString(R.string.alert_text_no_subnets));
			valid = false;
		}
		if (!validateSubnets(mExcludedSubnets))
		{
			mExcludedSubnetsWrap.setError(getString(R.string.alert_text_no_subnets));
			valid = false;
		}
		if (!validateInteger(mPort, 1, 65535))
		{
			mPortWrap.setError(String.format(getString(R.string.alert_text_out_of_range), 1, 65535));
			valid = false;
		}
		if (!validateInteger(mNATKeepalive, Constants.NAT_KEEPALIVE_MIN, Constants.NAT_KEEPALIVE_MAX))
		{
			mNATKeepaliveWrap.setError(String.format(getString(R.string.alert_text_out_of_range),
													 Constants.NAT_KEEPALIVE_MIN, Constants.NAT_KEEPALIVE_MAX));
			valid = false;
		}
		if (!validateProposal(mIkeProposal, true))
		{
			mIkeProposalWrap.setError(getString(R.string.alert_text_no_proposal));
			valid = false;
		}
		if (!validateProposal(mEspProposal, false))
		{
			mEspProposalWrap.setError(getString(R.string.alert_text_no_proposal));
			valid = false;
		}
		if (!validateAddresses(mDnsServers))
		{
			mDnsServersWrap.setError(getString(R.string.alert_text_no_ips));
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
		String name = getString(mName);
		String gateway = getString(mGateway);
		mProfile.setName(name == null ? gateway : name);
		mProfile.setGateway(gateway);
		mProfile.setVpnType(mVpnType);
		if (mVpnType.has(VpnTypeFeature.USER_PASS))
		{
			mProfile.setUsername(getString(mUsername));
			mProfile.setPassword(getString(mPassword));
		}
		if (mVpnType.has(VpnTypeFeature.CERTIFICATE))
		{
			mProfile.setUserCertificateAlias(mUserCertEntry.getAlias());
		}
		String certAlias = mCheckAuto.isChecked() ? null : mCertEntry.getAlias();
		mProfile.setCertificateAlias(certAlias);
		mProfile.setRemoteId(getString(mRemoteId));
		mProfile.setLocalId(getString(mLocalId));
		mProfile.setMTU(getInteger(mMTU));
		mProfile.setPort(getInteger(mPort));
		mProfile.setNATKeepAlive(getInteger(mNATKeepalive));
		int flags = 0;
		flags |= !mCertReq.isChecked() ? VpnProfile.FLAGS_SUPPRESS_CERT_REQS : 0;
		flags |= !mUseCrl.isChecked() ? VpnProfile.FLAGS_DISABLE_CRL : 0;
		flags |= !mUseOcsp.isChecked() ? VpnProfile.FLAGS_DISABLE_OCSP : 0;
		flags |= mStrictRevocation.isChecked() ? VpnProfile.FLAGS_STRICT_REVOCATION : 0;
		flags |= mRsaPss.isChecked() ? VpnProfile.FLAGS_RSA_PSS : 0;
		flags |= mIPv6Transport.isChecked() ? VpnProfile.FLAGS_IPv6_TRANSPORT : 0;
		mProfile.setFlags(flags);
		mProfile.setIncludedSubnets(getString(mIncludedSubnets));
		mProfile.setExcludedSubnets(getString(mExcludedSubnets));
		int st = 0;
		st |= mBlockIPv4.isChecked() ? VpnProfile.SPLIT_TUNNELING_BLOCK_IPV4 : 0;
		st |= mBlockIPv6.isChecked() ? VpnProfile.SPLIT_TUNNELING_BLOCK_IPV6 : 0;
		mProfile.setSplitTunneling(st == 0 ? null : st);
		mProfile.setSelectedAppsHandling(mSelectedAppsHandling);
		mProfile.setSelectedApps(mSelectedApps);
		mProfile.setIkeProposal(getString(mIkeProposal));
		mProfile.setEspProposal(getString(mEspProposal));
		mProfile.setDnsServers(getString(mDnsServers));
	}

	/**
	 * Load an existing profile if we got an ID
	 *
	 * @param savedInstanceState previously saved state
	 */
	private void loadProfileData(Bundle savedInstanceState)
	{
		String useralias = null, local_id = null, alias = null;
		Integer flags = null;

		getSupportActionBar().setTitle(R.string.add_profile);
		if (mUuid != null)
		{
			mProfile = mDataSource.getVpnProfile(mUuid);
			if (mProfile != null)
			{
				mName.setText(mProfile.getName());
				mGateway.setText(mProfile.getGateway());
				mVpnType = mProfile.getVpnType();
				mUsername.setText(mProfile.getUsername());
				mPassword.setText(mProfile.getPassword());
				mRemoteId.setText(mProfile.getRemoteId());
				mLocalId.setText(mProfile.getLocalId());
				mMTU.setText(mProfile.getMTU() != null ? mProfile.getMTU().toString() : null);
				mPort.setText(mProfile.getPort() != null ? mProfile.getPort().toString() : null);
				mNATKeepalive.setText(mProfile.getNATKeepAlive() != null ? mProfile.getNATKeepAlive().toString() : null);
				mIncludedSubnets.setText(mProfile.getIncludedSubnets());
				mExcludedSubnets.setText(mProfile.getExcludedSubnets());
				mBlockIPv4.setChecked(mProfile.getSplitTunneling() != null && (mProfile.getSplitTunneling() & VpnProfile.SPLIT_TUNNELING_BLOCK_IPV4) != 0);
				mBlockIPv6.setChecked(mProfile.getSplitTunneling() != null && (mProfile.getSplitTunneling() & VpnProfile.SPLIT_TUNNELING_BLOCK_IPV6) != 0);
				mSelectedAppsHandling = mProfile.getSelectedAppsHandling();
				mSelectedApps = mProfile.getSelectedAppsSet();
				mIkeProposal.setText(mProfile.getIkeProposal());
				mEspProposal.setText(mProfile.getEspProposal());
				mDnsServers.setText(mProfile.getDnsServers());
				mProfileId.setText(mProfile.getUUID().toString());
				flags = mProfile.getFlags();
				useralias = mProfile.getUserCertificateAlias();
				local_id = mProfile.getLocalId();
				alias = mProfile.getCertificateAlias();
				getSupportActionBar().setTitle(mProfile.getName());

				setReadOnly(mProfile.isReadOnly());
			}
			else
			{
				Log.e(VpnProfileDetailActivity.class.getSimpleName(),
					  "VPN profile with UUID " + mUuid + " not found");
				finish();
			}
		}

		mSelectVpnType.setSelection(mVpnType.ordinal());
		mCertReq.setChecked(flags == null || (flags & VpnProfile.FLAGS_SUPPRESS_CERT_REQS) == 0);
		mUseCrl.setChecked(flags == null || (flags & VpnProfile.FLAGS_DISABLE_CRL) == 0);
		mUseOcsp.setChecked(flags == null || (flags & VpnProfile.FLAGS_DISABLE_OCSP) == 0);
		mStrictRevocation.setChecked(flags != null && (flags & VpnProfile.FLAGS_STRICT_REVOCATION) != 0);
		mRsaPss.setChecked(flags != null && (flags & VpnProfile.FLAGS_RSA_PSS) != 0);
		mIPv6Transport.setChecked(flags != null && (flags & VpnProfile.FLAGS_IPv6_TRANSPORT) != 0);

		/* check if the user selected a user certificate previously */
		useralias = savedInstanceState == null ? useralias : savedInstanceState.getString(VpnProfileDataSource.KEY_USER_CERTIFICATE);
		if (useralias != null)
		{
			mUserCertLoading = useralias;
			UserCertificateLoader loader = new UserCertificateLoader(((StrongSwanApplication)getApplication()).getExecutor(),
																	 ((StrongSwanApplication)getApplication()).getHandler());
			loader.loadCertifiate(this, useralias, result -> {
				if (result != null)
				{
					mUserCertEntry = new TrustedCertificateEntry(mUserCertLoading, result);
				}
				else
				{	/* previously selected certificate is not here anymore */
					((TextView)mSelectUserCert.findViewById(android.R.id.text1)).setError("");
					mUserCertEntry = null;
				}
				mUserCertLoading = null;
				updateCredentialView();
			});
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

		mSelectSelectedAppsHandling.setSelection(mSelectedAppsHandling.ordinal());
		if (savedInstanceState != null)
		{
			ArrayList<String> selectedApps = savedInstanceState.getStringArrayList(VpnProfileDataSource.KEY_SELECTED_APPS_LIST);
			mSelectedApps = new TreeSet<>(selectedApps);
		}
	}

	private void setReadOnly(final boolean readOnly)
	{
		mManagedProfile.setVisibility(readOnly ? View.VISIBLE : View.GONE);

		mName.setEnabled(!readOnly);
		mGateway.setEnabled(!readOnly);
		mUsername.setEnabled(!readOnly);
		mRemoteId.setEnabled(!readOnly);
		mLocalId.setEnabled(!readOnly);
		mMTU.setEnabled(!readOnly);
		mPort.setEnabled(!readOnly);
		mNATKeepalive.setEnabled(!readOnly);
		mIncludedSubnets.setEnabled(!readOnly);
		mExcludedSubnets.setEnabled(!readOnly);
		mBlockIPv4.setEnabled(!readOnly);
		mBlockIPv6.setEnabled(!readOnly);
		mIkeProposal.setEnabled(!readOnly);
		mEspProposal.setEnabled(!readOnly);
		mDnsServers.setEnabled(!readOnly);

		mSelectVpnType.setEnabled(!readOnly);
		mCertReq.setEnabled(!readOnly);
		mUseCrl.setEnabled(!readOnly);
		mUseOcsp.setEnabled(!readOnly);
		mStrictRevocation.setEnabled(!readOnly);
		mRsaPss.setEnabled(!readOnly);
		mIPv6Transport.setEnabled(!readOnly);

		mCheckAuto.setEnabled(!readOnly);
		mSelectSelectedAppsHandling.setEnabled(!readOnly);

		findViewById(R.id.install_user_certificate).setEnabled(!readOnly);

		if (readOnly)
		{
			mSelectCert.setOnClickListener(null);
			mSelectUserCert.setOnClickListener(null);
		}
	}

	/**
	 * Get the string value in the given text box or null if empty
	 *
	 * @param view text box
	 */
	private String getString(EditText view)
	{
		String value = view.getText().toString().trim();
		return value.isEmpty() ? null : value;
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

	/**
	 * Check that the value in the given text box is a valid list of subnets/ranges
	 *
	 * @param view text box
	 */
	private boolean validateSubnets(EditText view)
	{
		String value = view.getText().toString().trim();
		return value.isEmpty() || IPRangeSet.fromString(value) != null;
	}

	/**
	 * Check that the value in the given text box is a valid list of IP addresses
	 *
	 * @param view text box
	 */
	private boolean validateAddresses(EditText view)
	{
		String value = view.getText().toString().trim();
		if (value.isEmpty())
		{
			return true;
		}
		for (String addr : value.split("\\s+"))
		{
			try
			{
				Utils.parseInetAddress(addr);
			}
			catch (UnknownHostException e)
			{
				return false;
			}
		}
		return true;
	}

	/**
	 * Check that the value in the given text box is a valid proposal
	 *
	 * @param view text box
	 */
	private boolean validateProposal(EditText view, boolean ike)
	{
		String value = view.getText().toString().trim();
		return value.isEmpty() || Utils.isProposalValid(ike, value);
	}

	private class SelectUserCertOnClickListener implements OnClickListener, KeyChainAliasCallback
	{
		@Override
		public void onClick(View v)
		{
			String useralias = mUserCertEntry != null ? mUserCertEntry.getAlias() : null;
			KeyChain.choosePrivateKeyAlias(VpnProfileDetailActivity.this, this, null, null, null, -1, useralias);
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
					runOnUiThread(new Runnable()
					{
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
	 * Callback interface for the user certificate loader.
	 */
	private interface UserCertificateLoaderCallback
	{
		void onComplete(X509Certificate result);
	}

	/**
	 * Load the selected user certificate asynchronously.  This cannot be done
	 * from the main thread as getCertificateChain() calls back to our main
	 * thread to bind to the KeyChain service resulting in a deadlock.
	 */
	private class UserCertificateLoader
	{
		private final Executor mExecutor;
		private final Handler mHandler;

		public UserCertificateLoader(Executor executor, Handler handler)
		{
			mExecutor = executor;
			mHandler = handler;
		}

		public void loadCertifiate(Context context, String alias, UserCertificateLoaderCallback callback)
		{
			mExecutor.execute(() -> {
				X509Certificate[] chain = null;
				try
				{
					chain = KeyChain.getCertificateChain(context, alias);
				}
				catch (KeyChainException | InterruptedException e)
				{
					e.printStackTrace();
				}
				if (chain != null && chain.length > 0)
				{
					complete(chain[0], callback);
					return;
				}
				complete(null, callback);
			});
		}

		protected void complete(X509Certificate result, UserCertificateLoaderCallback callback)
		{
			mHandler.post(() -> callback.onComplete(result));
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
				.setMessage(HtmlCompat.fromHtml(getString(R.string.tnc_notice_details), HtmlCompat.FROM_HTML_MODE_LEGACY))
				.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener()
				{
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
					TextUtils.copySpansFrom((Spanned)text, 0, text.length(), Object.class, sp, 0);
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

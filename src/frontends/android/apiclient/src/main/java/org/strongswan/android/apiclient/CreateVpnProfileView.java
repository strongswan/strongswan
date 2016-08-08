/*
 * Copyright © 2015 FancyFon Software Ltd.
 * All rights reserved.
 */
package org.strongswan.android.apiclient;

import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.res.Resources;
import android.os.Bundle;
import android.os.Message;
import android.os.RemoteException;
import android.text.TextUtils;
import android.view.View;
import android.widget.Button;
import android.widget.CheckedTextView;
import android.widget.EditText;
import com.fancyfon.strongswan.apiclient.R;
import com.google.inject.Inject;
import roboguice.activity.RoboActivity;
import roboguice.inject.ContentView;
import roboguice.inject.InjectView;

import java.util.ArrayList;
import java.util.Random;

/**
 * @author Marcin Waligórski <marcin.waligorski@fancyfon.com>
 */
@ContentView(R.layout.api_client_create_vpn_profile)
public class CreateVpnProfileView extends RoboActivity {

    private static final String TAG = CreateVpnProfileView.class.getSimpleName();
    private static final String SPACE = " ";
    private static final String NOTHING = "";

    @Inject
    Random random;
    @Inject
    Resources resources;
    @Inject
    Logger logger;
    @Inject
    VpnServiceConnector vpnServiceConnector;
    @Inject
    CertificateReader certificateReader;
    @Inject
    ReturnMessenger returnMessenger;
    @InjectView(R.id.vpn_name_edit_text)
    EditText vpnNameEditText;
    @InjectView(R.id.vpn_gateway_edit_text)
    EditText vpnGatewayEditText;
    @InjectView(R.id.vpn_username_edit_text)
    EditText vpnUsernameEditText;
    @InjectView(R.id.vpn_password_edit_text)
    EditText vpnPasswordEditText;
    @InjectView(R.id.vpn_user_certificate_password_edit_text)
    EditText vpnUserCertificatePasswordEditText;
    @InjectView(R.id.package_name_edit_text)
    EditText vpnPackageNameEditText;
    @InjectView(R.id.user_certificate)
    CheckedTextView vpnUserCertificateCheckedTextView;
    @InjectView(R.id.ca_certificate)
    CheckedTextView vpnCaCertificateCheckedTextView;
    @InjectView(R.id.vpn_type)
    Button vpnTypeButton;

    private String vpnType;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        vpnUserCertificateCheckedTextView.setOnClickListener(new View.OnClickListener() {
            public void onClick(View view) {
                checkUserCertificateClick(view);
            }
        });
        vpnCaCertificateCheckedTextView.setOnClickListener(new View.OnClickListener() {
            public void onClick(View view) {
                checkCaCertificateClick(view);
            }
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        vpnServiceConnector.connect();
    }

    @Override
    protected void onStop() {
        super.onStop();
        vpnServiceConnector.disconnect();
    }

    public void checkUserCertificateClick(View view) {
        vpnUserCertificateCheckedTextView.setChecked(!vpnUserCertificateCheckedTextView.isChecked());
        vpnUserCertificatePasswordEditText.setEnabled(vpnUserCertificateCheckedTextView.isChecked());
    }

    public void checkCaCertificateClick(View view) {
        vpnCaCertificateCheckedTextView.setChecked(!vpnCaCertificateCheckedTextView.isChecked());
    }

    public void selectVpnTypeClick(View view) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle("Choose vpn type")
                .setItems(R.array.array_vpn_type, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        vpnType = resources.getStringArray(R.array.array_vpn_type)[which];
                        vpnTypeButton.setText(vpnType);
                    }
                });
        AlertDialog dialog =  builder.create();
        dialog.show();
    }

    public void clickCreateVpnProfile(View view) {
        if(verifyThatMandatoryFieldsAreSet()) {
            Bundle vpnProfile = prepareVpnProfile();
            if (vpnProfile != null) {
                sendProfileViaMessenger(vpnProfile);
            } else {
                logger.logAndToast(TAG, "Error creating profile. Vpn not created");
            }
        }
    }

    private void sendProfileViaMessenger(Bundle vpnProfile) {
        try {
            Message message = Message.obtain(null, getResources().getInteger(R.integer.vpn_profile_create_message), random.nextInt(), 0);
            message.setData(vpnProfile);
            message.replyTo = returnMessenger.getReturnMessenger();
            try {
                vpnServiceConnector.getMessenger().send(message);
            } catch (RemoteException e) {
                logger.logAndToast(TAG, "Error creating profile. Vpn not created", e);
            }
        } catch (Exception e) {
            logger.logAndToast(TAG, "Error creating profile. Vpn not created", e);
        }
    }

    private Bundle prepareVpnProfile() {
        Bundle vpnProfile = new Bundle();
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_name_key), vpnNameEditText.getText().toString());
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_gateway_key), vpnGatewayEditText.getText
                ().toString().replace(SPACE, NOTHING));
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_type_key), vpnType);

        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_username_key), vpnUsernameEditText
                .getText().toString().replace(SPACE, NOTHING));
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_password_key), vpnPasswordEditText
                .getText().toString().replace(SPACE, NOTHING));
        if (!addCaCertificate(vpnProfile)) {
            return null;
        }
        if (!addUserCertificate(vpnProfile)) {
            return null;
        }
        ArrayList<String> packages = new ArrayList<String>();
        packages.add(vpnPackageNameEditText.getText().toString().replace(SPACE, NOTHING));
        vpnProfile.putStringArrayList(resources.getString(R.string.vpn_profile_bundle_allowed_applications), packages);
        return vpnProfile;
    }

    private boolean addUserCertificate(Bundle vpnProfile) {
        if(vpnUserCertificateCheckedTextView.isChecked()) {
            String userCert = certificateReader.getUserCertificate();
            if(userCert == null) {
                return false;
            }
            vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_user_certificate_key),
                    userCert);
            vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_user_certificate_password_key),
                    vpnUserCertificatePasswordEditText.getText().toString().replace(SPACE, NOTHING));
        }
        return true;
    }

    private boolean addCaCertificate(Bundle vpnProfile) {
        if(vpnCaCertificateCheckedTextView.isChecked()) {
            String caCert = certificateReader.getCaCertificate();
            if(caCert == null) {
                return false;
            }
            vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_certificate_key),
                    caCert);
        }
        return true;
    }

    private boolean verifyThatMandatoryFieldsAreSet() {
        if(TextUtils.isEmpty(vpnNameEditText.getText())) {
            logger.logAndToast(TAG, "Vpn name is not set");
            return false;
        }
        if(TextUtils.isEmpty(vpnGatewayEditText.getText())) {
            logger.logAndToast(TAG, "Vpn gateway is not set");
            return false;
        }
        if(TextUtils.isEmpty(vpnType)) {
            logger.logAndToast(TAG, "Vpn type is not set");
            return false;
        }
        return true;
    }
}
package org.strongswan.android.apiclient;

import android.content.Intent;
import android.content.res.Resources;
import android.os.Bundle;
import android.os.Message;
import android.os.RemoteException;
import android.text.TextUtils;
import android.view.View;
import android.widget.EditText;
import android.widget.RadioButton;
import com.fancyfon.strongswan.apiclient.R;
import com.google.inject.Inject;
import roboguice.activity.RoboActivity;
import roboguice.inject.ContentView;
import roboguice.inject.InjectView;

import java.util.ArrayList;
import java.util.List;

@ContentView(R.layout.api_client_activity)
public class ApiClientActivity extends RoboActivity {
    public static final String TAG = "strongSwanApiClient";
    public static final int SERVICE_IPC_TYPE = 0;
    public static final int MESSENGER_IPC_TYPE = 1;

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
    @InjectView(R.id.messenger_radio_button)
    RadioButton messengerRadioButton;
    @InjectView(R.id.service_radio_button)
    RadioButton serviceRadioButton;
    @InjectView(R.id.package_name_edit_text)
    EditText packageNameEditText;
    @InjectView(R.id.profile_id_edit_text)
    EditText vpnProfileIdEditText;

    private  ArrayList<String>allowedApps;
    private int ipcType = MESSENGER_IPC_TYPE;

    @Override
    protected void onDestroy() {
        super.onDestroy();
        vpnServiceConnector.disconnect();
    }

    public void clickReadVpnProfiles(View view) {
        if (ipcType == MESSENGER_IPC_TYPE) {
            sendViaMessenger(getResources().getInteger(R.integer.vpn_profile_read_all_message), "failed to get vpn " +
                    "profiles via messenger");
        } else {
            readProfilesViaService();
        }
    }

    private void readProfilesViaService() {
        if (vpnServiceConnector.getService() != null) {
            try {
                List<Bundle> vpnProfiles = vpnServiceConnector.getService().readVpnProfiles();
                for (Bundle bundle : vpnProfiles) {
                    logger.logAndToastVpnProfileBundle(TAG, bundle);
                }
            } catch (RemoteException e) {
                logger.logAndToast(TAG, "failed to get vpn profiles via service", e);
            }
        } else {
            logger.logAndToast(TAG, "not connected to service");
        }
    }

    public void clickDisconnectFromStrongSwan(View view) {
        vpnServiceConnector.disconnect();
    }

    public void clickConnectToStrongSwan(View view) {
        boolean result = vpnServiceConnector.connectToService();
        logger.logAndToast(TAG, "bind successful to service? " + result);
        result = vpnServiceConnector.connectToMessengerService();
        logger.logAndToast(TAG, "bind successful to messenger service? " + result);
    }

    public void clickCreateVpnProfile(View view) {
        allowedApps = new ArrayList<String>();
        allowedApps.add( packageNameEditText.getText().toString());
        Bundle eapBundle = getEapBundle();
        Bundle certBundle = getCertBundle();
        if (ipcType == MESSENGER_IPC_TYPE) {
            if(eapBundle != null) {
                sendViaMessenger(getResources().getInteger(R.integer.vpn_profile_create_message), eapBundle, "failed " +
                        "to add eap vpn profile via service");
            }
            if(certBundle != null) {
                sendViaMessenger(getResources().getInteger(R.integer.vpn_profile_create_message), certBundle, "failed to add cert vpn profile via service");
            }
        } else {
            createVpnProfileViaService(eapBundle, certBundle);
        }
    }

    private void createVpnProfileViaService(Bundle eapBundle, Bundle certBundle) {
        if (vpnServiceConnector.getService() != null) {
            if(eapBundle != null) {
                addEapProfileViaService(eapBundle);
            }
            if(certBundle != null) {
                addCertProfileViaService(certBundle);
            }
        } else {
            logger.logAndToast(TAG, "not connected to service");
        }
    }

    private void addCertProfileViaService(Bundle certBundle) {
        try {
            boolean result = vpnServiceConnector.getService().createVpnProfile(certBundle);
            logger.logAndToast(TAG, "was cert vpn profile added? " + result);
        } catch (Exception e) {
            logger.logAndToast(TAG, "failed to add cert vpn profile via service", e);
        }
    }

    private void addEapProfileViaService(Bundle eapBundle) {
        try {
            boolean result = vpnServiceConnector.getService().createVpnProfile(eapBundle);
            logger.logAndToast(TAG, "was eap vpn profile added? " + result);
        } catch (Exception e) {
            logger.logAndToast(TAG, "failed to add eap vpn profile via service", e);
        }
    }

    private Bundle getEapBundle() {
        Bundle vpnProfile = new Bundle();
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_name_key), "eap famocvpn");
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_gateway_key), "famocvpn.emdmcloud.com");
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_username_key), "john");
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_password_key), "pass123");
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_type_key), resources.getString(R.string.vpn_profile_bundle_type_ikev2_eap_value));
        vpnProfile.putStringArrayList(resources.getString(R.string.vpn_profile_bundle_allowed_applications), allowedApps);
        return vpnProfile;
    }

    private Bundle getCertBundle() {
        Bundle vpnProfile = new Bundle();
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_name_key), "cert famocvpn");
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_gateway_key), "famocvpn.emdmcloud.com");
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_type_key), resources.getString(R.string.vpn_profile_bundle_type_ikev2_cert_value));
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_user_certificate_password_key),
                "pass");
        if (addCertToBundle(vpnProfile)) {
            return null;
        }
        vpnProfile.putStringArrayList(resources.getString(R.string.vpn_profile_bundle_allowed_applications), allowedApps);
        return vpnProfile;
    }

    private boolean addCertToBundle(Bundle vpnProfile) {
        String caCert = certificateReader.getCaCertificate();
        String userCert = certificateReader.getUserCertificate();
        if(caCert == null || userCert == null) {
            logger.logAndToast(TAG, "Error creating cert bundle. Vpn failed to create.");
            return true;
        }
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_certificate_key), caCert);
        vpnProfile.putString(resources.getString(R.string.vpn_profile_bundle_user_certificate_key), userCert);
        return false;
    }

    public void clickCreateVpnProfileActivity(View view) {
        startActivity(new Intent(this, CreateVpnProfileView.class));
    }

    public void clickService(View view) {
        ipcType = SERVICE_IPC_TYPE;
        serviceRadioButton.setChecked(true);
        messengerRadioButton.setChecked(false);
    }

    public void clickMessenger(View view) {
        ipcType = MESSENGER_IPC_TYPE;
        serviceRadioButton.setChecked(false);
        messengerRadioButton.setChecked(true);
    }

    public void clickDeleteVpnProfiles(View view) {
        if (ipcType == MESSENGER_IPC_TYPE) {
            sendViaMessenger(getResources().getInteger(R.integer.vpn_profile_delete_all_message), "failed to delete vpn profiles via messenger");
        } else {
            if (vpnServiceConnector.getService() != null) {
                try {
                    boolean result = vpnServiceConnector.getService().deleteVpnProfiles();
                    logger.logAndToast(TAG, "was any vpn profiles deleted? " + result);
                } catch (RemoteException e) {
                    logger.logAndToast(TAG, "failed to delete vpn profiles via service", e);
                }
            } else {
                logger.logAndToast(TAG, "not connected to service");
            }
        }

    }

    public void clickDeleteVpnProfile(View view) {
        if(!TextUtils.isEmpty(vpnProfileIdEditText.getText())) {
            if (ipcType == MESSENGER_IPC_TYPE) {
                try {
                    Bundle bundle = new Bundle();
                    bundle.putString(resources.getString(R.string.vpn_profile_bundle_name_key), vpnProfileIdEditText
                            .getText().toString());
                    sendViaMessenger(getResources().getInteger(R.integer.vpn_profile_delete_message), bundle, "failed to " +
                            "delete vpn profiles via messenger");
                } catch (NumberFormatException e) {
                    logger.logAndToast(TAG, "Invalid value for id.");
                }

            } else {
                if (vpnServiceConnector.getService() != null) {
                    try {
                        boolean result = vpnServiceConnector.getService().deleteVpnProfile(vpnProfileIdEditText.getText().toString());
                        logger.logAndToast(TAG, "was any vpn profiles deleted? " + result);
                    } catch (RemoteException e) {
                        logger.logAndToast(TAG, "failed to delete vpn profiles via service", e);
                    }
                } else {
                    logger.logAndToast(TAG, "not connected to service");
                }
            }
        } else {
            logger.logAndToast(TAG, "No vpn profile id");
        }
    }

    private void sendViaMessenger(int messageType, String loggerMessage) {
        sendViaMessenger(messageType, 0, loggerMessage);
    }

    private void sendViaMessenger(int messageType, int messageArgument, String loggerMessage) {
        sendViaMessenger(messageType, messageArgument, null, loggerMessage);
    }

    private void sendViaMessenger(int messageType, Bundle bundle, String loggerMessage) {
        sendViaMessenger(messageType, 0, bundle, loggerMessage);
    }

    private void sendViaMessenger(int messageType, int messageArgument, Bundle bundle, String loggerMessage) {
        if (vpnServiceConnector.getMessenger() != null) {
            Message message = Message.obtain(null, messageType, messageArgument, 0);
            if (bundle != null) {
                message.setData(bundle);
            }
            message.replyTo = returnMessenger.getReturnMessenger();
            try {
                vpnServiceConnector.getMessenger().send(message);
            } catch (RemoteException e) {
                logger.logAndToast(TAG, loggerMessage, e);
            }
        } else {
            logger.logAndToast(TAG, "not connected to messenger");
        }
    }
}


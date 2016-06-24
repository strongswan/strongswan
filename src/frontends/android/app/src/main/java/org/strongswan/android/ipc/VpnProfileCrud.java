/*
 * Copyright © 2013 FancyFon Software Ltd.
 * All rights reserved.
 * 
 * $Id$
 * 
 */
package org.strongswan.android.ipc;

import android.content.Context;
import android.database.SQLException;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;

import org.strongswan.android.R;
import org.strongswan.android.data.VpnProfile;
import org.strongswan.android.data.VpnProfileDataSource;
import org.strongswan.android.security.LocalKeystore;

import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.List;

/**
 * @author Piotr Soróbka <piotr.sorobka@fancyfon.com>
 */
public class VpnProfileCrud {

    private static final String TAG = VpnProfileCrud.class.getSimpleName();
    private final VpnProfileDataSource source;
    private final Context context;
    private LocalKeystore localKeystore;


    public VpnProfileCrud(Context context) {
        this.context = context;
        source = new VpnProfileDataSource(context);
        try {
            source.open();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean createVpnProfile(Bundle vpnProfile) {
        return installCertificatesFromBundle(vpnProfile) &&  source.insertProfile(new VpnProfile(vpnProfile, context
                .getResources())) != null;
    }

    public Bundle readVpnProfile(String name) {
        VpnProfile vpnProfile = source.getVpnProfile(name);
        if (vpnProfile == null) {
            return null;
        }
        return vpnProfile.toBundle(context.getResources());
    }

    public Bundle readVpnProfile(long id) {
        VpnProfile vpnProfile = source.getVpnProfile(id);
        if (vpnProfile == null) {
            return null;
        }
        return vpnProfile.toBundle(context.getResources());
    }

    public List<Bundle> readVpnProfiles() {
        List<VpnProfile> allVpnProfiles = source.getAllVpnProfiles();
        List<Bundle> bundles = new ArrayList<Bundle>(allVpnProfiles.size());
        for (VpnProfile profile : allVpnProfiles) {
            bundles.add(profile.toBundle(context.getResources()));
        }
        return bundles;
    }

    public boolean updateVpnProfile(Bundle vpnProfile) {
        return installCertificatesFromBundle(vpnProfile) &&  source.updateVpnProfile(new VpnProfile(vpnProfile, context.getResources()));
    }

    public boolean deleteVpnProfile(String name) {
        VpnProfile profile = source.getVpnProfile(name);
        boolean result = source.deleteVpnProfile(profile);
        if(result && profile != null) {
            return deleteCertificate(profile.getCertificateId());
        }
        return result;
    }

    public boolean deleteVpnProfiles() {
        boolean deleteAllResult = true;
        boolean deleteOneResult;
        List<VpnProfile> allVpnProfiles = source.getAllVpnProfiles();
        for (VpnProfile profile : allVpnProfiles) {
            deleteOneResult = source.deleteVpnProfile(profile);
            if(deleteOneResult) {
                deleteOneResult &= deleteCertificate(profile.getCertificateId());
            }
            deleteAllResult &= deleteOneResult;
        }
        return deleteAllResult;
    }

    public boolean deleteCertificate(String certificateId) {
        try {
            createLocalKeystore();
            return localKeystore.removePkcs12AndCaCertificate(certificateId);
        } catch (KeyStoreException e) {
            Log.e(TAG, "Error deleting certificate: " + e);
        }
        return false;
    }

    public void close() {
        source.close();
    }

    private boolean installCertificatesFromBundle(Bundle vpnProfile) {
        try {
            if(isThereUserOrCaCertificateInBundle(vpnProfile)) {
                Log.d(TAG, "At least one certificate is in bundle.");
                createLocalKeystore();
                String id = generateAndSetCertificateIdInBundle(vpnProfile);
                installUserCertificateFromBundle(vpnProfile, id);
                installCaCertificateFromBundle(vpnProfile, id);
            } else {
                Log.d(TAG, "No certificate in bundle.");
            }
            return true;
        } catch (Throwable e) {
            Log.e(TAG, "Error installing certificate: " + e);
        }
        return false;
    }

    private boolean isThereUserOrCaCertificateInBundle(Bundle vpnProfile) {
        return isUserCertificateInBundle(vpnProfile) || isCaCertificateInBundle(vpnProfile);
    }

    private boolean isCaCertificateInBundle(Bundle vpnProfile) {
        return !TextUtils.isEmpty(vpnProfile.getString(
                context.getResources().getString(R.string.vpn_profile_bundle_certificate_key)));
    }

    private boolean isUserCertificateInBundle(Bundle vpnProfile) {
        return !TextUtils.isEmpty(vpnProfile.getString(
                context.getResources().getString(R.string.vpn_profile_bundle_user_certificate_key)));
    }

    private void installCaCertificateFromBundle(Bundle vpnProfile, String id) throws Exception {
        if(isCaCertificateInBundle(vpnProfile)) {
            Log.i(TAG, "Installing CA certificate.");
            String certAlias = localKeystore.addCaCertificate(Base64.decode(vpnProfile.getString(context.getResources()
                    .getString(R.string.vpn_profile_bundle_certificate_key)), Base64.DEFAULT), id);
            if(certAlias != null) {
                vpnProfile.putString(context.getResources().getString(R.string.vpn_profile_bundle_certificate_alias_key),
                        certAlias);
            } else {
                throw new Exception("Failed to install CA certificate");
            }
        }
    }

    private void installUserCertificateFromBundle(Bundle vpnProfile, String id) throws Exception {
        if(isUserCertificateInBundle(vpnProfile)) {
            Log.i(TAG, "Installing user certificate.");
            String userAlias = localKeystore.addPkcs12(Base64.decode(vpnProfile.getString(
                            context.getResources().getString(R.string.vpn_profile_bundle_user_certificate_key)),
                    Base64.DEFAULT), vpnProfile.getString(context.getResources().getString(R.string
                    .vpn_profile_bundle_user_certificate_password_key)), id);
            if(userAlias != null) {
                vpnProfile.putString(context.getResources().getString(R.string.vpn_profile_bundle_user_certificate_alias_key),
                        userAlias);
            } else {
                throw new Exception("Failed to install user certificate");
            }
        }
    }

    private String generateAndSetCertificateIdInBundle(Bundle vpnProfile) {
        Log.i(TAG, "Generating id.");
        String id = localKeystore.generateId();
        vpnProfile.putString(context.getResources().getString(R.string.vpn_profile_bundle_certificate_id_key), id);
        return id;
    }

    private void createLocalKeystore() throws KeyStoreException {
        if(localKeystore == null) {
            localKeystore = new LocalKeystore();
        }
    }
}

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
import org.strongswan.android.data.VpnProfile;
import org.strongswan.android.data.VpnProfileDataSource;

import java.util.ArrayList;
import java.util.List;

/**
 * @author Piotr Soróbka <piotr.sorobka@fancyfon.com>
 */
public class VpnProfileCrud {

    private final VpnProfileDataSource source;
    private final Context context;

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
        return source.insertProfile(new VpnProfile(vpnProfile, context.getResources())) != null;
    }

    public Bundle readVpnProfile(long l) {
        VpnProfile vpnProfile = source.getVpnProfile(l);
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
        return source.updateVpnProfile(new VpnProfile(vpnProfile, context.getResources()));
    }

    public boolean deleteVpnProfile(long l) {
        VpnProfile profile = new VpnProfile();
        profile.setId(l);
        return source.deleteVpnProfile(profile);
    }

    public boolean deleteVpnProfiles() {
        boolean result = false;
        List<VpnProfile> allVpnProfiles = source.getAllVpnProfiles();
        for (VpnProfile profile : allVpnProfiles) {
            result = source.deleteVpnProfile(profile);
        }
        return result;
    }

    public void close() {
        source.close();
    }
}

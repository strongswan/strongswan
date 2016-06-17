package org.strongswan.android.ipc;

interface VpnProfileCrudService {

    boolean createVpnProfile(in Bundle profile);

    Bundle readVpnProfile(long id);

    List<Bundle> readVpnProfiles();

    boolean updateVpnProfile(in Bundle profile);

    boolean deleteVpnProfile(String profileName);

    boolean deleteVpnProfiles();

}
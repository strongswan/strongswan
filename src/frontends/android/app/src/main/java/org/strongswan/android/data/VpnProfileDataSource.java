/*
 * Copyright (C) 2023 Relution GmbH
 * Copyright (C) 2012-2019 Tobias Brunner
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

package org.strongswan.android.data;

import android.database.SQLException;

import java.util.List;
import java.util.UUID;

public interface VpnProfileDataSource
{
	String KEY_ID = "_id";
	String KEY_UUID = "_uuid";
	String KEY_NAME = "name";
	String KEY_GATEWAY = "gateway";
	String KEY_VPN_TYPE = "vpn_type";
	String KEY_USERNAME = "username";
	String KEY_PASSWORD = "password";
	String KEY_CERTIFICATE = "certificate";
	String KEY_USER_CERTIFICATE = "user_certificate";
	String KEY_USER_CERTIFICATE_PASSWORD = "user_certificate_password";
	String KEY_MTU = "mtu";
	String KEY_PORT = "port";
	String KEY_SPLIT_TUNNELING = "split_tunneling";
	String KEY_LOCAL_ID = "local_id";
	String KEY_REMOTE_ID = "remote_id";
	String KEY_EXCLUDED_SUBNETS = "excluded_subnets";
	String KEY_INCLUDED_SUBNETS = "included_subnets";
	String KEY_SELECTED_APPS = "selected_apps";
	String KEY_SELECTED_APPS_LIST = "selected_apps_list";
	String KEY_NAT_KEEPALIVE = "nat_keepalive";
	String KEY_FLAGS = "flags";
	String KEY_IKE_PROPOSAL = "ike_proposal";
	String KEY_ESP_PROPOSAL = "esp_proposal";
	String KEY_DNS_SERVERS = "dns_servers";
	String KEY_READ_ONLY = "read_only";

	/**
	 * Open the VPN profile data source. The database is automatically created
	 * if it does not yet exist. If that fails an exception is thrown.
	 *
	 * @return itself (allows to chain initialization calls)
	 * @throws SQLException if the database could not be opened or created
	 */
	VpnProfileDataSource open() throws SQLException;

	/**
	 * Close the data source.
	 */
	void close();

	/**
	 * Insert the given VPN profile into the database.  On success the Id of
	 * the object is updated and the object returned.
	 *
	 * @param profile the profile to add
	 * @return the added VPN profile or null, if failed
	 */
	VpnProfile insertProfile(VpnProfile profile);

	/**
	 * Updates the given VPN profile in the database.
	 *
	 * @param profile the profile to update
	 * @return true if update succeeded, false otherwise
	 */
	boolean updateVpnProfile(VpnProfile profile);

	/**
	 * Delete the given VPN profile from the database.
	 *
	 * @param profile the profile to delete
	 * @return true if deleted, false otherwise
	 */
	boolean deleteVpnProfile(VpnProfile profile);

	/**
	 * Get a single VPN profile from the database by its UUID.
	 *
	 * @param uuid the UUID of the VPN profile
	 * @return the profile or null, if not found
	 */
	VpnProfile getVpnProfile(UUID uuid);

	/**
	 * Get a single VPN profile from the database by its UUID as String.
	 *
	 * @param uuid the UUID of the VPN profile as String
	 * @return the profile or null, if not found
	 */
	default VpnProfile getVpnProfile(String uuid)
	{
		try
		{
			if (uuid != null)
			{
				return getVpnProfile(UUID.fromString(uuid));
			}
			return null;
		}
		catch (IllegalArgumentException e)
		{
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Get a list of all VPN profiles stored in the database.
	 *
	 * @return list of VPN profiles
	 */
	List<VpnProfile> getAllVpnProfiles();
}

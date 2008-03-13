
INSERT INTO ike_configs (
	certreq, force_encap, local, remote
) VALUES (
	0, 0, '0.0.0.0', '152.96.52.150'
);

INSERT INTO child_configs (
	name, lifetime, rekeytime, jitter, updown, hostaccess, mode
) VALUES (
	'sqltest', 500, 400, 50, NULL, 1, 1
);

INSERT INTO peer_config_child_config (
	peer_cfg, child_cfg
) VALUES (
	1, 1
);

INSERT INTO traffic_selectors (
	type, protocol
) values (
	7, 0
);

INSERT INTO child_config_traffic_selector (
	child_cfg, traffic_selector, kind
) VALUES (
	1, 1, 2
);

INSERT INTO child_config_traffic_selector (
	child_cfg, traffic_selector, kind
) VALUES (
	1, 1, 3
);

INSERT INTO peer_configs (
	name, ike_version, ike_cfg, local_id, remote_id, cert_policy, auth_method, 
	eap_type, eap_vendor, keyingtries, rekeytime, reauthtime, jitter, overtime, 
	mobike, dpd_delay, dpd_action, local_vip, remote_vip, 
	mediation, mediated_by, peer_id
) VALUES (
	'sqltest', 2, 1, 'C=CH, O=Linux strongSwan, CN=martin', 'sidv0150.hsr.ch', 0, 0, 
	0, 0, 0, 500, 2000, 20, 20,
	1, 120, 0, NULL, NULL, 0, 0, NULL
);

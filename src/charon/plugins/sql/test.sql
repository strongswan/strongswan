
INSERT INTO ike_configs (
	local, remote
) VALUES (
	'0.0.0.0', '152.96.52.150'
);

INSERT INTO child_configs (
	name
) VALUES (
	'sqltest'
);

INSERT INTO peer_config_child_config (
	peer_cfg, child_cfg
) VALUES (
	1, 1
);

INSERT INTO traffic_selectors (type) VALUES (7);

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
	name, ike_cfg, local_id, remote_id
) VALUES (
	'sqltest', 1, 'C=CH, O=Linux strongSwan, CN=martin', 'sidv0150.hsr.ch'
);

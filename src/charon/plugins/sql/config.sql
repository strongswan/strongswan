
DROP TABLE IF EXISTS ike_configs;
CREATE TABLE ike_configs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	certreq INTEGER,
	force_encap INTEGER,
	local TEXT, 
	remote TEXT
);

DROP TABLE IF EXISTS child_configs;
CREATE TABLE child_configs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT,
	lifetime INTEGER,
	rekeytime INTEGER,
	jitter INTEGER,
	updown TEXT,
	hostaccess INTEGER,
	mode INTEGER
);

DROP TABLE IF EXISTS peer_config_child_config;
CREATE TABLE peer_config_child_config (
	peer_cfg INTEGER,
	child_cfg INTEGER
);

DROP TABLE IF EXISTS traffic_selectors;
CREATE TABLE traffic_selectors (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	type INTEGER,
	protocol INTEGER,
	start_addr TEXT,
	end_addr TEXT,
	start_port INTEGER,
	end_port INTEGER
);

DROP TABLE IF EXISTS child_config_traffic_selector;
CREATE TABLE child_config_traffic_selector (
	child_cfg INTEGER,
	traffic_selector INTEGER,
	kind INTEGER
);

DROP TABLE IF EXISTS peer_configs;
CREATE TABLE peer_configs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT,
	ike_version INTEGER,
	ike_cfg INTEGER,
	local_id TEXT,
	remote_id TEXT,
	cert_policy INTEGER,
	auth_method INTEGER,
	eap_type INTEGER,
	eap_vendor INTEGER,
	keyingtries INTEGER, 
	rekeytime INTEGER, 
	reauthtime INTEGER, 
	jitter INTEGER, 
	overtime INTEGER,
	mobike INTEGER,
	dpd_delay INTEGER, 
	dpd_action INTEGER,
	local_vip TEXT,
	remote_vip TEXT,
	mediation INTEGER,
	mediated_by INTEGER,
	peer_id TEXT
);

